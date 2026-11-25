"""Bounded, read-only Wazuh indexer queries. No LLM calls or rule changes."""
import base64
import hashlib
import json
import os
import re
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .core import Invalid, load_json_bounded
from .intake import summarize_events

INDICES = {'alerts': 'wazuh-alerts-*', 'archives': 'wazuh-archives-*'}
MAX_RESPONSE_BYTES = 2_000_000
CONFIG_FIELDS = {'url', 'username', 'password_env', 'ca_file'}


class CollectionError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validate_config(config):
    if not isinstance(config, dict) or set(config) != CONFIG_FIELDS:
        raise Invalid('Cấu hình indexer cần url, username, password_env, ca_file; không lưu password')
    if not all(isinstance(value, str) and value.strip() for value in config.values()):
        raise Invalid('Cấu hình indexer có trường rỗng hoặc sai kiểu')
    try:
        parsed = urlsplit(config['url'])
        port = parsed.port
    except ValueError:
        raise Invalid('URL indexer không hợp lệ') from None
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in ('', '/')
            or parsed.query or parsed.fragment or (port is not None and not 1 <= port <= 65535)):
        raise Invalid('Cần URL gốc HTTPS của indexer, không kèm tài khoản/path/query')
    if any(ord(ch) <= 32 for ch in config['url']) or ':' in config['username']:
        raise Invalid('URL hoặc username không hợp lệ')
    if not re.fullmatch(r'NEXUS_[A-Z0-9_]+', config['password_env']):
        raise Invalid('Tên biến mật khẩu phải bắt đầu NEXUS_ và chỉ gồm chữ hoa/số/underscore')
    return dict(config, url=config['url'].rstrip('/'))


def load_config(path):
    try:
        with Path(path).open(encoding='utf-8-sig') as stream:
            text = stream.read(8193)
        if len(text) > 8192:
            raise Invalid('Cấu hình indexer quá lớn')
        return validate_config(load_json_bounded(text))
    except FileNotFoundError:
        raise CollectionError('not_configured') from None
    except (ValueError, UnicodeError, OSError):
        raise CollectionError('invalid_config') from None


def connection_status(path):
    try:
        config = load_config(path)
    except CollectionError as exc:
        return {'configured': False, 'code': exc.code}
    return {'configured': True, 'url': config['url'], 'username': config['username'],
            'credential_available': bool(os.environ.get(config['password_env'])),
            'ca_available': Path(config['ca_file']).is_file(), 'tls_verification': True,
            'connected': False}


def build_query(source='alerts', minutes=60, limit=100, agent_id='', now=None):
    if not isinstance(source, str) or source not in INDICES:
        raise Invalid('Nguồn phải là alerts hoặc archives')
    if type(minutes) is not int or not 1 <= minutes <= 1440:
        raise Invalid('Cửa sổ đọc phải từ 1 đến 1440 phút')
    if type(limit) is not int or not 1 <= limit <= 500:
        raise Invalid('Số event cần đọc phải từ 1 đến 500')
    if not isinstance(agent_id, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{0,128}', agent_id):
        raise Invalid('Agent ID không hợp lệ')
    ended = now if now is not None else datetime.now(timezone.utc)
    started = ended - timedelta(minutes=minutes)
    window = {'gte': started.isoformat(), 'lt': ended.isoformat()}
    filters = [{'range': {'timestamp': window}}]
    if agent_id:
        filters.append({'term': {'agent.id': agent_id}})
    payload = {'size': limit, 'track_total_hits': True, 'timeout': '10s',
               'query': {'bool': {'filter': filters}}, 'sort': [{'timestamp': {'order': 'desc'}}]}
    return payload, window


def _request(config, body, source):
    password = os.environ.get(config['password_env'])
    if not password:
        raise CollectionError('credentials_missing')
    try:
        context = ssl.create_default_context(cafile=config['ca_file'])
    except (OSError, ssl.SSLError):
        raise CollectionError('ca_invalid') from None
    # No ambient HTTP proxy and no redirects carrying the Authorization header.
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())
    endpoint = (config['url'] + '/' + INDICES[source]
                + '/_search?allow_partial_search_results=false&allow_no_indices=false&ignore_unavailable=false')
    auth = base64.b64encode((config['username'] + ':' + password).encode()).decode('ascii')
    request = Request(endpoint, data=body, method='POST',
                      headers={'Content-Type': 'application/json', 'Authorization': 'Basic ' + auth})
    try:
        with opener.open(request, timeout=15) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        status = exc.code
        exc.close()
        raise CollectionError({401: 'authentication_failed', 403: 'permission_denied',
                               404: 'index_unavailable'}.get(status, 'http_error')) from None
    except (ssl.SSLError, URLError, OSError) as exc:
        reason = exc.reason if isinstance(exc, URLError) else exc
        code = 'tls_error' if isinstance(reason, ssl.SSLError) else 'network_error'
        raise CollectionError(code) from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CollectionError('response_too_large')
    try:
        return load_json_bounded(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise CollectionError('invalid_response') from None


def collect(config_path, source='alerts', minutes=60, limit=100, agent_id=''):
    payload, window = build_query(source, minutes, limit, agent_id)
    config = load_config(config_path)
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    result = _request(config, body, source)
    try:
        if not isinstance(result, dict):
            raise ValueError()
        shards = result['_shards']
        if result['timed_out'] is not False:
            raise CollectionError('query_timed_out')
        for field in ('total', 'successful', 'failed'):
            if type(shards[field]) is not int or shards[field] < 0:
                raise ValueError()
        if shards['failed'] or shards['total'] != shards['successful']:
            raise CollectionError('partial_results')
        total = result['hits']['total']
        hits = result['hits']['hits']
        if (not isinstance(total, dict) or type(total['value']) is not int or total['value'] < 0
                or total['relation'] != 'eq' or not isinstance(hits, list)
                or len(hits) > limit or len(hits) > total['value']):
            raise ValueError()
        documents, seen = [], set()
        for hit in hits:
            identifier, index, event = hit['_id'], hit['_index'], hit['_source']
            if (not isinstance(identifier, str) or not identifier or not isinstance(index, str)
                    or not index.startswith(INDICES[source][:-1]) or not isinstance(event, dict)):
                raise ValueError()
            pair = (index, identifier)
            if pair in seen:
                raise ValueError()
            seen.add(pair)
            documents.append({'index': index, 'id': identifier, 'event': event})
        preview = summarize_events([d['event'] for d in documents], source, 'lab') if documents else None
    except CollectionError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError):
        raise CollectionError('invalid_response') from None
    if not hits and total['value'] > 0:
        raise CollectionError('invalid_response')
    return {'status': 'ok', 'source': source, 'window': window, 'agent_id': agent_id,
            'returned': len(documents), 'total_matching': total['value'],
            'truncated': total['value'] > len(documents), 'limit': limit,
            'query_sha256': hashlib.sha256(body).hexdigest(),
            'documents': documents, 'preview': preview,
            'provenance': 'indexer_read_only_query_not_research_verdict',
            'persisted': False, 'external_send_allowed': False,
            'limitations': ['Chỉ đọc dữ liệu đã index trong cửa sổ; chưa phải collector liên tục.',
                            'Thiếu alert/event chưa chứng minh tấn công hoặc Wazuh bỏ sót.',
                            'Chưa gửi LLM, chưa xác minh nhãn hoặc tạo run nghiên cứu.']}
