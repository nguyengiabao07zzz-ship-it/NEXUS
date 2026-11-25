import copy
import io
import json
import os
import ssl
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nexus import indexer
from nexus.core import Invalid
import test_review_fixes as fixtures

TMP = Path(__file__).resolve().parents[1] / 'tmp' / 'tests'
TMP.mkdir(parents=True, exist_ok=True)
CONFIG = {'url': 'https://192.168.157.130:9200', 'username': 'fixture_reader',
          'password_env': 'NEXUS_INDEXER_PASSWORD', 'ca_file': 'fixture-ca.pem'}
EVENT = {'timestamp': '2026-11-24T10:00:00Z', 'agent': {'id': '001'},
         'rule': {'id': '100901'}, 'full_log': 'fixture only'}


def response(count=1):
    return {'timed_out': False, '_shards': {'total': 1, 'successful': 1, 'failed': 0},
            'hits': {'total': {'value': count, 'relation': 'eq'},
                     'hits': [{'_index': 'wazuh-alerts-4.x-2026.11.24', '_id': 'fixture-1', '_source': EVENT}] if count else []}}


class IndexerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.tmp.cleanup)
        self.config_path = Path(self.tmp.name) / 'indexer.json'
        self.config_path.write_text(json.dumps(CONFIG), encoding='utf-8')

    def collect(self, result, **kwargs):
        with patch('nexus.indexer._request', return_value=result):
            return indexer.collect(self.config_path, **kwargs)

    def test_query_pins_window_agent_and_size(self):
        payload, window = indexer.build_query('alerts', 60, 20, '001', datetime(2026, 11, 24, 10, tzinfo=timezone.utc))
        self.assertEqual(window, {'gte': '2026-11-24T09:00:00+00:00', 'lt': '2026-11-24T10:00:00+00:00'})
        self.assertEqual(payload['size'], 20)
        self.assertTrue(payload['track_total_hits'])
        self.assertEqual(payload['query']['bool']['filter'][1], {'term': {'agent.id': '001'}})
        for kwargs in ({'source': ['alerts']}, {'source': '../_all'}, {'minutes': True},
                       {'limit': 501}, {'agent_id': {'match_all': {}}}):
            with self.assertRaises(Invalid):
                indexer.build_query(**kwargs)

    def test_config_rejects_plaintext_password_http_and_url_credentials(self):
        for config in [dict(CONFIG, password='CANARY'), dict(CONFIG, url='http://host:9200'),
                       dict(CONFIG, url='https://user:pass@host:9200'),
                       dict(CONFIG, url='https://host/_search'), dict(CONFIG, password_env='PATH')]:
            with self.assertRaises(Invalid):
                indexer.validate_config(config)
        self.assertFalse(indexer.connection_status(self.config_path)['connected'])
        self.assertEqual(indexer.connection_status(Path(self.tmp.name) / 'missing.json')['code'], 'not_configured')

    def test_collection_retains_document_ids_and_marks_truncation(self):
        result = self.collect(response(4), limit=1)
        self.assertEqual(result['returned'], 1)
        self.assertEqual(result['total_matching'], 4)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['documents'][0]['id'], 'fixture-1')
        self.assertEqual(result['preview']['total_events'], 1)
        self.assertFalse(result['persisted'])
        self.assertFalse(result['external_send_allowed'])
        self.assertNotIn('outcome', result)

    def test_empty_success_does_not_create_no_log_verdict(self):
        result = self.collect(response(0))
        self.assertEqual(result['documents'], [])
        self.assertIsNone(result['preview'])
        self.assertNotIn('outcome', result)

    def test_partial_timeout_and_bad_responses_are_not_success(self):
        timeout = response(); timeout['timed_out'] = True
        partial = response(); partial['_shards'] = {'total': 2, 'successful': 1, 'failed': 1}
        inexact = response(); inexact['hits']['total']['relation'] = 'gte'
        missing = response(); missing['hits']['hits'][0].pop('_source')
        duplicated = response(2); duplicated['hits']['hits'] *= 2
        for result, code in [(timeout, 'query_timed_out'), (partial, 'partial_results'),
                             (inexact, 'invalid_response'), (missing, 'invalid_response'),
                             (duplicated, 'invalid_response'), ({}, 'invalid_response')]:
            with self.subTest(code=code), self.assertRaises(indexer.CollectionError) as exc:
                self.collect(result)
            self.assertEqual(exc.exception.code, code)

    def test_archives_without_rule_supported_and_wrong_index_rejected(self):
        data = response()
        data['hits']['hits'][0]['_index'] = 'wazuh-archives-4.x-2026.11.24'
        data['hits']['hits'][0]['_source'] = dict(EVENT)
        data['hits']['hits'][0]['_source'].pop('rule')
        self.assertEqual(self.collect(data, source='archives')['preview']['events_without_rule_id'], 1)
        with self.assertRaises(indexer.CollectionError):
            self.collect(data, source='alerts')


class TransportTests(unittest.TestCase):
    def test_password_setup_refuses_noninteractive_stdin(self):
        from nexus.server import main
        with patch('sys.argv', ['run_nexus.py', '--ask-indexer-password']), \
             patch('sys.stdin.isatty', return_value=False), \
             patch('nexus.server.getpass.getpass') as prompt, \
             patch('sys.stderr', new=io.StringIO()):
            with self.assertRaises(SystemExit) as exc:
                main()
            self.assertEqual(exc.exception.code, 1)
            prompt.assert_not_called()

    def test_verified_tls_no_proxy_no_redirect_and_only_search(self):
        with patch.dict(os.environ, NEXUS_INDEXER_PASSWORD='CANARY-TRANSPORT-PASSWORD'), \
             patch('nexus.indexer.ssl.create_default_context') as context, \
             patch('nexus.indexer.build_opener') as builder:
            connection = builder.return_value.open.return_value.__enter__.return_value
            connection.read.return_value = json.dumps(response()).encode()
            indexer._request(CONFIG, b'{}', 'alerts')
            context.assert_called_once_with(cafile='fixture-ca.pem')
            handlers = builder.call_args.args
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsInstance(handlers[2], indexer.NoRedirect)
            self.assertIsNone(handlers[2].redirect_request(None, None, 302, None, None, 'https://other/'))
            request = builder.return_value.open.call_args.args[0]
            self.assertEqual(request.method, 'POST')
            self.assertIn('/wazuh-alerts-*/_search?', request.full_url)
            self.assertIn('allow_partial_search_results=false', request.full_url)
            self.assertNotIn('CANARY', request.full_url)
            connection.read.assert_called_once_with(indexer.MAX_RESPONSE_BYTES + 1)

    def test_auth_permission_index_and_tls_errors_do_not_echo_secrets(self):
        errors = [(HTTPError('https://fixture', code, 'CANARY-ERROR', {}, io.BytesIO(b'CANARY')), expected)
                  for code, expected in [(401, 'authentication_failed'), (403, 'permission_denied'),
                                         (404, 'index_unavailable'), (302, 'http_error')]]
        errors += [(URLError(ssl.SSLError('CANARY-TLS')), 'tls_error'),
                   (URLError(OSError('CANARY-NETWORK')), 'network_error')]
        for error, expected in errors:
            with patch.dict(os.environ, NEXUS_INDEXER_PASSWORD='CANARY-PASSWORD'), \
                 patch('nexus.indexer.ssl.create_default_context'), \
                 patch('nexus.indexer.build_opener') as builder:
                builder.return_value.open.side_effect = error
                with self.assertRaises(indexer.CollectionError) as exc:
                    indexer._request(CONFIG, b'{}', 'alerts')
                self.assertEqual(exc.exception.code, expected)
                self.assertNotIn('CANARY', str(exc.exception))

    def test_missing_password_does_not_make_network_request(self):
        with patch.dict(os.environ, {}, clear=True), patch('nexus.indexer.build_opener') as builder:
            with self.assertRaises(indexer.CollectionError) as exc:
                indexer._request(CONFIG, b'{}', 'alerts')
            self.assertEqual(exc.exception.code, 'credentials_missing')
            builder.assert_not_called()


class IndexerHTTPTests(unittest.TestCase):
    setUp = fixtures.HTTPFixes.setUp
    tearDown = fixtures.HTTPFixes.tearDown
    request = fixtures.HTTPFixes.request

    def test_status_collection_and_failures_do_not_modify_store(self):
        self.assertEqual(self.request('GET', '/api/indexer/status', headers={'X-Nexus-Token': 'wrong'})[0], 403)
        self.assertFalse(self.request('GET', '/api/indexer/status')[1]['configured'])
        (Path(self.tmp.name) / 'indexer.json').write_text(json.dumps(CONFIG), encoding='utf-8')
        with patch('nexus.indexer._request', return_value=response()):
            status, result = self.request('POST', '/api/indexer/collect', {'source': 'alerts', 'limit': 10})
        self.assertEqual(status, 200)
        self.assertEqual(result['returned'], 1)
        self.assertEqual(self.request('GET', '/api/state')[1]['records'], [])
        with patch('nexus.indexer._request', side_effect=indexer.CollectionError('permission_denied')):
            status, result = self.request('POST', '/api/indexer/collect', {})
        self.assertEqual(status, 502)
        self.assertEqual(result['code'], 'permission_denied')
        self.assertEqual(self.request('POST', '/api/indexer/collect', {'password': 'CANARY'})[0], 400)
