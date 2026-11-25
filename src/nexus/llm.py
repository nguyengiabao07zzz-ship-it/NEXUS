"""OpenAI Responses adapter: one bounded request after application approval."""
import json
import os
import re
import ssl
import subprocess
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from .core import Invalid, load_json_bounded
from .indexer import NoRedirect

ENDPOINTS = {'openai': 'https://api.openai.com/v1/responses',
             'codex_cli': 'Codex CLI tại máy → dịch vụ Codex (đăng nhập ChatGPT)'}
KEY_ENV = 'NEXUS_OPENAI_API_KEY'
MAX_RESPONSE_BYTES = 256_000
WINDOWS = os.name == 'nt'


def tls_context():
    context = ssl.create_default_context()
    # Some Windows Python distributions have neither a CA bundle nor the
    # ssl module's Windows-store integration. Import public trusted roots only.
    if WINDOWS and context.cert_store_stats()['x509_ca'] == 0:
        script = "$ErrorActionPreference='Stop'; foreach ($location in 'LocalMachine','CurrentUser') { $store=New-Object System.Security.Cryptography.X509Certificates.X509Store('Root',$location); try { $store.Open('ReadOnly'); foreach ($cert in $store.Certificates) { '-----BEGIN CERTIFICATE-----'; [Convert]::ToBase64String($cert.RawData); '-----END CERTIFICATE-----' } } finally { $store.Close() } }"
        shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        try:
            result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', script],
                                    capture_output=True, timeout=15, check=True)
            context.load_verify_locations(cadata=result.stdout.decode('ascii'))
        except (OSError, subprocess.SubprocessError, UnicodeError, ssl.SSLError):
            raise AIError('ai_tls_error') from None
    return context


class AIError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def validate_config(config):
    if (not isinstance(config, dict) or set(config) != {'provider', 'model', 'max_output_tokens'}
            or config['provider'] not in ENDPOINTS):
        raise Invalid('Cấu hình AI cần provider=openai/codex_cli, model, max_output_tokens; không chứa credential')
    if (not isinstance(config['model'], str) or config['model'] == 'YOUR_MODEL_ID'
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}', config['model'])):
        raise Invalid('Model ID không hợp lệ')
    if type(config['max_output_tokens']) is not int or not 512 <= config['max_output_tokens'] <= 4096:
        raise Invalid('Giới hạn output phải từ 512 đến 4096 token')
    return dict(config)


def load_config(path):
    try:
        with Path(path).open(encoding='utf-8-sig') as stream:
            text = stream.read(8193)
        if len(text) > 8192:
            raise ValueError()
        return validate_config(load_json_bounded(text))
    except FileNotFoundError:
        raise AIError('ai_not_configured') from None
    except (ValueError, UnicodeError, OSError):
        raise AIError('ai_invalid_config') from None


def key_available(config):
    if config['provider'] == 'codex_cli':
        from .codex_cli import readiness
        return readiness()['ready']
    return bool(os.environ.get(KEY_ENV))


def status(path):
    try:
        config = load_config(path)
    except AIError as exc:
        return {'configured': False, 'code': exc.code}
    readiness = {}
    if config['provider'] == 'codex_cli':
        from .codex_cli import readiness as check
        readiness = check()
    return {'configured': True, 'provider': config['provider'], 'model': config['model'],
            'destination': ENDPOINTS[config['provider']],
            'key_available': readiness['ready'] if readiness else key_available(config),
            'max_output_tokens': config['max_output_tokens'] if config['provider'] == 'openai' else None,
            'readiness_code': readiness.get('code'), 'automatic_send': False}


def output_schema(refs):
    text = {'type': 'string'}
    finding = {'type': 'object', 'additionalProperties': False,
               'properties': {'title': text, 'severity': {'type': 'string', 'enum': ['info', 'low', 'medium', 'high', 'critical']},
                              'assessment': {'type': 'string', 'enum': ['suspicious', 'possibly_benign', 'insufficient_context']},
                              'evidence_refs': {'type': 'array', 'items': {'type': 'string', 'enum': refs}},
                              'explanation': text, 'recommended_checks': {'type': 'array', 'items': text}},
               'required': ['title', 'severity', 'assessment', 'evidence_refs', 'explanation', 'recommended_checks']}
    return {'type': 'object', 'additionalProperties': False,
            'properties': {'summary': text, 'findings': {'type': 'array', 'items': finding},
                           'limitations': {'type': 'array', 'items': text}},
            'required': ['summary', 'findings', 'limitations']}


def build_request(config, system_prompt, content, purpose='triage'):
    from .rules import schema as draft_schema
    if purpose not in ('triage','rule_draft'):
        raise Invalid('AI purpose không hợp lệ')
    refs = [item['ref'] for item in content['evidence']]
    schema = draft_schema(refs) if purpose=='rule_draft' else output_schema(refs)
    schema_name = 'nexus_rule_draft' if purpose=='rule_draft' else 'nexus_triage'
    if config['provider'] == 'codex_cli':
        return {'model': config['model'], 'transport': 'codex_cli_chatgpt',
                'sandbox': 'read-only', 'tools_disabled': True,
                'prompt': system_prompt + '\nKhông gọi công cụ, không đọc file hoặc chạy lệnh. Chỉ trả JSON theo schema.\n' + json.dumps(content, ensure_ascii=False, sort_keys=True),
                'schema_name':schema_name, 'schema': schema}
    refs = [item['ref'] for item in content['evidence']]
    return {'model': config['model'], 'store': False, 'max_output_tokens': config['max_output_tokens'],
            'input': [{'role': 'system', 'content': [{'type': 'input_text', 'text': system_prompt}]},
                      {'role': 'user', 'content': [{'type': 'input_text', 'text': json.dumps(content, ensure_ascii=False, sort_keys=True)}]}],
            'text': {'format': {'type': 'json_schema', 'name': schema_name, 'strict': True,
                                'schema': schema}}}


def validate_output(value, refs, payload):
    name=payload.get('schema_name',payload.get('text',{}).get('format',{}).get('name','nexus_triage'))
    if name=='nexus_rule_draft':
        from .rules import validate_draft
        return 'draft',validate_draft(value,refs)
    if name!='nexus_triage':raise AIError('ai_invalid_output')
    return 'analysis',validate_analysis(value,refs)


def _text(value, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError()


def validate_analysis(value, refs):
    try:
        if not isinstance(value, dict) or set(value) != {'summary', 'findings', 'limitations'}:
            raise ValueError()
        _text(value['summary'], 2000)
        if not isinstance(value['findings'], list) or len(value['findings']) > 10:
            raise ValueError()
        if not isinstance(value['limitations'], list) or not 1 <= len(value['limitations']) <= 10:
            raise ValueError()
        for limitation in value['limitations']:
            _text(limitation, 500)
        for finding in value['findings']:
            if not isinstance(finding, dict) or set(finding) != {
                    'title', 'severity', 'assessment', 'evidence_refs', 'explanation', 'recommended_checks'}:
                raise ValueError()
            _text(finding['title'], 160)
            _text(finding['explanation'], 2000)
            if finding['severity'] not in ('info', 'low', 'medium', 'high', 'critical'):
                raise ValueError()
            if finding['assessment'] not in ('suspicious', 'possibly_benign', 'insufficient_context'):
                raise ValueError()
            cited = finding['evidence_refs']
            if (not isinstance(cited, list) or not cited or len(cited) > 20
                    or any(not isinstance(ref, str) or ref not in refs for ref in cited)
                    or len(set(cited)) != len(cited)):
                raise ValueError()
            checks = finding['recommended_checks']
            if not isinstance(checks, list) or not 1 <= len(checks) <= 8:
                raise ValueError()
            for check in checks:
                _text(check, 500)
    except (KeyError, TypeError, ValueError):
        raise AIError('ai_invalid_output') from None
    return value


def _unique(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError()
        value[name] = item
    return value


def _json(text):
    return load_json_bounded(text, object_pairs_hook=_unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def call(config, payload, refs):
    if config['provider'] == 'codex_cli':
        from .codex_cli import call as codex_call
        return codex_call(config, payload, refs)
    key = os.environ.get(KEY_ENV)
    if not key:
        raise AIError('ai_key_missing')
    body = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=tls_context()), NoRedirect())
    request = Request(ENDPOINTS[config['provider']], data=body, method='POST',
                      headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + key})
    try:
        with opener.open(request, timeout=45) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        code = exc.code
        exc.close()
        raise AIError({401: 'ai_auth_failed', 403: 'ai_permission_denied',
                       429: 'ai_rate_or_quota'}.get(code, 'ai_http_error')) from None
    except ssl.SSLCertVerificationError:
        raise AIError('ai_tls_error') from None
    except (OSError, URLError, ssl.SSLError) as exc:
        if isinstance(getattr(exc, 'reason', None), ssl.SSLCertVerificationError):
            raise AIError('ai_tls_error') from None
        # A failed/uncertain network request is never retried automatically.
        raise AIError('ai_network_error') from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AIError('ai_response_too_large')
    try:
        result = _json(raw)
        if result.get('status') != 'completed':
            raise AIError('ai_incomplete')
        parts = []
        for item in result['output']:
            if item.get('type') == 'reasoning':
                continue
            if item.get('type') != 'message':
                raise ValueError()
            for content in item['content']:
                if content.get('type') == 'refusal':
                    raise AIError('ai_refused')
                if content.get('type') != 'output_text':
                    raise ValueError()
                parts.append(content['text'])
        if not parts:
            raise ValueError()
        result_key, analysis = validate_output(_json(''.join(parts)), refs, payload)
        usage = {name: number for name, number in result.get('usage', {}).items()
                 if name in ('input_tokens', 'output_tokens', 'total_tokens')
                 and type(number) is int and number >= 0}
        model = result.get('model')
        identifier = result.get('id')
        return {result_key: analysis, 'model': config['model'], 'provider': config['provider'],
                'response_model': model if isinstance(model, str) and len(model) <= 128 else None,
                'response_id': identifier if isinstance(identifier, str) and len(identifier) <= 128 else None,
                'usage': usage, 'execution_mode': 'openai_responses_api'}
    except AIError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise AIError('ai_invalid_output') from None
