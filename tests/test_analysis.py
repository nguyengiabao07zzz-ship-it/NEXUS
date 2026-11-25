import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nexus.analysis import AnalysisService, canonical, digest, project_event, TTL_SECONDS
from nexus import llm
from nexus.core import Invalid
import test_review_fixes as fixtures

CONFIG = {'provider': 'openai', 'model': 'fixture-model', 'max_output_tokens': 2048}
EVENT = {'timestamp': '2026-11-24T10:00:00.123+0700', 'agent': {'id': '001', 'name': 'CANARY-HOST'},
         'rule': {'id': '100901', 'level': 3}, 'full_log': 'CANARY-RAW-LOG',
         'data': {'user': 'CANARY-USER', 'password': 'CANARY-SECRET', 'version': '192.168.1.10'}}


def collection():
    return {'status': 'ok', 'source': 'alerts', 'window': {'gte': '2026-11-23T00:00:00Z', 'lt': '2026-11-24T00:00:00Z'},
            'truncated': False, 'documents': [{'index': 'wazuh-alerts-fixture', 'id': 'fixture-id', 'event': copy.deepcopy(EVENT)}]}


def valid_analysis(ref='E1'):
    return {'summary': 'Fixture only; not a real model analysis.',
            'findings': [{'title': 'Insufficient context', 'severity': 'info', 'assessment': 'insufficient_context',
                          'evidence_refs': [ref], 'explanation': 'Many fields are blocked.',
                          'recommended_checks': ['Review the original event locally.']}],
            'limitations': ['Synthetic fixture, not threat evidence.']}


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[1] / 'tmp' / 'tests'
        base.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'ai.json'
        self.path.write_text(json.dumps(CONFIG), encoding='utf-8')
        self.now = [0]
        self.service = AnalysisService(b'a'*32, self.path, self.root / 'requests', lambda: self.now[0])
        self.snapshot = self.service.remember(collection())

    def preview(self):
        return self.service.prepare(self.snapshot, [1])

    def test_preview_contains_no_canary_and_keeps_local_mapping_out_of_request(self):
        with patch('nexus.llm.call') as caller:
            preview = self.preview()
            caller.assert_not_called()
        text = json.dumps(preview, ensure_ascii=False)
        self.assertNotIn('CANARY-', text)
        self.assertNotIn('192.168.1.10', text)
        self.assertNotIn('fixture-id', json.dumps(preview['request']))
        self.assertEqual(preview['local_references'][0]['id'], 'fixture-id')
        self.assertEqual(preview['request_sha256'], digest(preview['request']))
        self.assertFalse(preview['external_send_allowed'])
        self.assertEqual(preview['redacted_content']['evidence'][0]['content']['timestamp'], '2026-11-24T10:00:00.123000+07:00')
        self.assertIn('ambiguous_version_ipv4', preview['review_flags'])
        self.assertFalse((self.root / 'requests').exists())

    def test_finite_cache_and_snapshot_input_validation(self):
        for indexes in ([], [0], [2], [True], [1,1], list(range(1,22))):
            with self.subTest(indexes=indexes), self.assertRaises(Invalid):
                self.service.prepare(self.snapshot, indexes)
        for _ in range(5):
            self.service.remember(collection())
        self.assertEqual(len(self.service.snapshots), 4)
        with self.assertRaises(Invalid):
            self.preview()

    def test_no_approval_wrong_hash_expiration_or_missing_key_never_calls_provider(self):
        preview = self.preview()
        with patch('nexus.llm.call') as caller, patch.dict(os.environ, {}, clear=True):
            for approved, value in [(False, preview['request_sha256']), ('yes', preview['request_sha256']), (True, 'wrong')]:
                with self.assertRaises(Invalid):
                    self.service.run(preview['preview_id'], value, approved)
            with self.assertRaises(llm.AIError) as exc:
                self.service.run(preview['preview_id'], preview['request_sha256'], True)
            self.assertEqual(exc.exception.code, 'ai_key_missing')
            self.now[0] += TTL_SECONDS + 1
            with self.assertRaises(Invalid):
                self.service.run(preview['preview_id'], preview['request_sha256'], True)
            caller.assert_not_called()

    def test_configuration_change_invalidates_approval(self):
        preview = self.preview()
        self.path.write_text(json.dumps(dict(CONFIG, model='changed-model')), encoding='utf-8')
        with patch('nexus.llm.call') as caller, self.assertRaises(Invalid):
            self.service.run(preview['preview_id'], preview['request_sha256'], True)
        caller.assert_not_called()

    def test_single_use_success_audits_exact_request_without_key_or_raw_logs(self):
        preview = self.preview()
        answer = {'analysis': valid_analysis(), 'usage': {'input_tokens': 10}, 'execution_mode': 'fixture_adapter'}
        with patch.dict(os.environ, NEXUS_OPENAI_API_KEY='CANARY-API-KEY'), patch('nexus.llm.call', return_value=answer) as caller:
            result = self.service.run(preview['preview_id'], preview['request_sha256'], True)
            with self.assertRaises(Invalid):
                self.service.run(preview['preview_id'], preview['request_sha256'], True)
            self.assertEqual(caller.call_count, 1)
        self.assertTrue(result['human_review_required'])
        self.assertFalse(result['actions_executed'])
        self.assertFalse(result['candidate_created'])
        requests = list((self.root/'requests').glob('*/request.json'))
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].read_bytes(), canonical(preview['request']))
        for path in (self.root/'requests').rglob('*.json'):
            self.assertNotIn('CANARY-', path.read_text(encoding='utf-8'))

    def test_provider_error_consumes_ticket_and_never_retries(self):
        preview = self.preview()
        with patch.dict(os.environ, NEXUS_OPENAI_API_KEY='fixture-key'), patch('nexus.llm.call', side_effect=llm.AIError('ai_network_error')) as caller:
            with self.assertRaises(llm.AIError):
                self.service.run(preview['preview_id'], preview['request_sha256'], True)
            with self.assertRaises(Invalid):
                self.service.run(preview['preview_id'], preview['request_sha256'], True)
            caller.assert_called_once()

    def test_busy_request_does_not_consume_another_approval(self):
        preview = self.preview()
        self.service.inflight.acquire()
        try:
            with patch.dict(os.environ, NEXUS_OPENAI_API_KEY='fixture-key'), patch('nexus.llm.call') as caller:
                with self.assertRaises(llm.AIError) as exc:
                    self.service.run(preview['preview_id'], preview['request_sha256'], True)
                self.assertEqual(exc.exception.code, 'ai_busy')
                self.assertEqual(self.service.previews[preview['preview_id']]['state'], 'ready')
                caller.assert_not_called()
        finally:
            self.service.inflight.release()

    def test_storage_failure_happens_before_any_api_call(self):
        preview = self.preview()
        with patch.dict(os.environ, NEXUS_OPENAI_API_KEY='fixture-key'), \
             patch('pathlib.Path.mkdir', side_effect=OSError('CANARY-STORAGE')), \
             patch('nexus.llm.call') as caller:
            with self.assertRaises(llm.AIError) as exc:
                self.service.run(preview['preview_id'], preview['request_sha256'], True)
            self.assertEqual(exc.exception.code, 'ai_storage_error')
            self.assertNotIn('CANARY', str(exc.exception))
            caller.assert_not_called()
        self.assertFalse(self.service.inflight.locked())

    def test_unconfigured_preview_still_works_without_a_send_path(self):
        self.path.unlink()
        preview = self.preview()
        self.assertFalse(preview['configured'])
        self.assertIsNone(preview['request'])
        with patch('nexus.llm.call') as caller, self.assertRaises(llm.AIError):
            self.service.run(preview['preview_id'], preview['request_sha256'], True)
        caller.assert_not_called()


class AnalysisHTTPTests(unittest.TestCase):
    setUp = fixtures.HTTPFixes.setUp
    tearDown = fixtures.HTTPFixes.tearDown
    request = fixtures.HTTPFixes.request

    def test_indexer_snapshot_to_local_preview_and_no_unapproved_send(self):
        (Path(self.tmp.name)/'ai.json').write_text(json.dumps(CONFIG), encoding='utf-8')
        with patch('nexus.server.indexer.collect', return_value=collection()):
            status, result = self.request('POST','/api/indexer/collect',{})
        self.assertEqual(status, 200)
        status, preview = self.request('POST','/api/ai/preview',{'snapshot_id': result['snapshot_id'], 'event_indexes':[1]})
        self.assertEqual(status, 200)
        with patch('nexus.llm.call') as caller:
            status, _ = self.request('POST','/api/ai/run',{'preview_id':preview['preview_id'], 'request_sha256':preview['request_sha256'], 'approved':False})
            self.assertEqual(status, 400)
            caller.assert_not_called()
        self.assertEqual(self.request('GET','/api/ai/status',headers={'X-Nexus-Token':'wrong'})[0],403)
        self.assertEqual(self.request('GET','/api/state')[1]['records'],[])
        self.assertEqual(self.request('POST','/api/ai/preview',{'documents': [EVENT]})[0],400)
