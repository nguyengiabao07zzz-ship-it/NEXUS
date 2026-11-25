import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nexus.core import Invalid
from nexus.intake import inspect_events, MAX_EVENTS, MAX_TEXT_BYTES
import test_review_fixes as fixtures


FIXTURE = Path(__file__).parent / 'fixtures' / 'wazuh_sysmon_process_create.synthetic.json'


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.event = json.loads(FIXTURE.read_text(encoding='utf-8'))

    def preview(self, events, source='alerts'):
        text = events if isinstance(events, str) else json.dumps(events)
        return inspect_events(text, source, 'fixture')

    def test_json_jsonl_bom_preserve_counts_and_indexes(self):
        other = copy.deepcopy(self.event)
        other['agent']['id'] = 'another-agent'
        for text in (json.dumps([self.event, self.event, other]),
                     '\ufeff' + '\n'.join(json.dumps(e) for e in [self.event, self.event, other])):
            p = self.preview(text)
            self.assertEqual(p['total_events'], 3)
            self.assertEqual(p['repeated_content_count'], 1)
            self.assertEqual([g['event_indexes'] for g in p['groups']], [[1, 2], [3]])
            self.assertFalse(p['persisted'])
            self.assertFalse(p['external_send_allowed'])
            self.assertNotIn('full_log', json.dumps(p))
            self.assertNotIn('CANARY-', json.dumps(p))

    def test_archives_without_rule_is_not_a_miss(self):
        self.event.pop('rule')
        p = self.preview(self.event, 'archives')
        self.assertEqual(p['events_without_rule_id'], 1)
        self.assertNotIn('outcome', p)
        with self.assertRaises(Invalid):
            self.preview(self.event, 'alerts')

    def test_bad_line_rejects_whole_batch_without_echoing_log(self):
        text = json.dumps(self.event) + '\n{"secret":"CANARY-INVALID"'
        with self.assertRaises(Invalid) as exc:
            self.preview(text)
        self.assertIn('2', str(exc.exception))
        self.assertNotIn('CANARY', str(exc.exception))

    def test_strict_json_shapes_and_limits(self):
        for value in ('[]', 'null', '[1]', '{"timestamp":NaN}', '{"agent":{},"agent":{}}',
                      '[{"agent": []}]', '[' * 70 + '0' + ']' * 70):
            with self.subTest(value=value[:30]), self.assertRaises(Invalid):
                self.preview(value)
        with self.assertRaises(Invalid):
            self.preview([self.event] * (MAX_EVENTS + 1))
        with self.assertRaises(Invalid):
            self.preview('x' * (MAX_TEXT_BYTES + 1))
        for field in ('source', 'origin'):
            args = dict(text=json.dumps(self.event), source='alerts', origin='fixture')
            args[field] = 'unknown'
            with self.assertRaises(Invalid):
                inspect_events(**args)

    def test_different_rules_and_decoders_are_not_merged(self):
        rule = copy.deepcopy(self.event)
        rule['rule']['id'] = '999999'
        decoder = copy.deepcopy(self.event)
        decoder['decoder']['name'] = 'different-decoder'
        self.assertEqual(len(self.preview([self.event, rule, decoder])['groups']), 3)


class IntakeHTTPTests(unittest.TestCase):
    setUp = fixtures.HTTPFixes.setUp
    tearDown = fixtures.HTTPFixes.tearDown
    request = fixtures.HTTPFixes.request

    def test_preview_is_authenticated_and_does_not_create_records(self):
        event = json.loads(FIXTURE.read_text(encoding='utf-8'))
        data = dict(text=json.dumps(event), source='alerts', origin='fixture')
        # No upload body on the rejected request: Windows may reset connections
        # closed by the existing HTTP server while request bytes remain unread.
        self.assertEqual(self.request('POST', '/api/logs/preview', None, {'X-Nexus-Token': 'wrong'})[0], 403)
        status, preview = self.request('POST', '/api/logs/preview', data)
        self.assertEqual(status, 200)
        self.assertEqual(preview['total_events'], 1)
        self.assertFalse(preview['external_send_allowed'])
        self.assertEqual(self.request('GET', '/api/state')[1]['records'], [])
        self.assertEqual(self.request('POST', '/api/logs/preview', dict(data, text='broken'))[0], 400)
