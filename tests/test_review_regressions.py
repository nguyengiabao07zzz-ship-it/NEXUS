"""Regressions reported against da84d3e; fixtures never contact a lab."""
import copy
import json
import os
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from nexus import indexer
from nexus.core import Invalid, Store
from nexus.intake import inspect_events, MAX_TEXT_BYTES
import test_core as core_fixtures
import test_indexer as indexer_fixtures
import test_review_fixes as http_fixtures


class HeldOutRegressionTests(unittest.TestCase):
    setUp = core_fixtures.WorkflowTests.setUp
    run_data = core_fixtures.WorkflowTests.run_data
    candidate = core_fixtures.WorkflowTests.candidate

    def held_out(self):
        return self.s.add('case', dict(title='Held-out fixture', technique='T1059',
            source='synthetic', criteria='independent evaluation', environment='fixture', split='held_out'))

    def test_development_candidate_can_be_evaluated_on_held_out_without_being_changed(self):
        candidate = self.candidate()
        held = self.held_out()
        run = self.s.add('run', self.run_data(case_id=held['id'], phase='tuned',
                                             candidate_id=candidate['id'], alert_matches=True))
        self.assertEqual(run['case_id'], held['id'])
        self.assertEqual(run['outcome'], 'detected')
        self.assertEqual(run['candidate_sha256'], candidate['sha256'])
        self.assertEqual(run['candidate_source_case_id'], self.case['id'])
        self.assertEqual(self.s.get(candidate['id']), candidate)
        self.assertEqual(Store(self.s.path).get(run['id']), run)
        self.assertEqual(self.s.report()['groups']['fixture']['phases']['tuned']['detected'], 1)

    def test_development_cases_still_require_their_own_candidate(self):
        candidate = self.candidate()
        other = self.s.add('case', dict(title='Other development fixture', technique='T1059',
            source='synthetic', criteria='other scenario', environment='fixture', split='development'))
        with self.assertRaises(Invalid):
            self.s.add('run', self.run_data(case_id=other['id'], phase='tuned', candidate_id=candidate['id']))

    def test_held_out_candidate_creation_and_baseline_with_candidate_remain_blocked(self):
        candidate = self.candidate()
        held = self.held_out()
        with self.assertRaises(Invalid): self.candidate(case_id=held['id'])
        with self.assertRaises(Invalid): self.candidate(case_id=held['id'], parent_id=candidate['id'])
        with self.assertRaises(Invalid):
            self.s.add('run', self.run_data(case_id=held['id'], phase='baseline', candidate_id=candidate['id']))

    def test_legacy_candidate_from_held_out_is_not_accepted_for_evaluation(self):
        candidate = self.candidate()
        held = self.held_out()
        legacy = {name:value for name,value in candidate.items() if name not in ('id','kind','created')}
        legacy['case_id'] = held['id']
        with self.s.connect() as db:
            db.execute('INSERT INTO records VALUES (?,?,?,?)',('legacy-held-candidate','candidate','legacy',json.dumps(legacy)))
        with self.assertRaises(Invalid):
            self.s.add('run', self.run_data(case_id=held['id'],phase='tuned',candidate_id='legacy-held-candidate'))

    def test_client_cannot_spoof_candidate_version_metadata(self):
        candidate = self.candidate()
        with self.assertRaises(Invalid):
            self.s.add('run',self.run_data(phase='tuned',candidate_id=candidate['id'],candidate_source_case_id='spoofed'))


class IndexerSizeRegressionTests(unittest.TestCase):
    setUp = indexer_fixtures.IndexerTests.setUp

    def collect_raw(self, raw):
        with patch.dict(os.environ, NEXUS_INDEXER_PASSWORD='CANARY-fixture'), \
             patch('nexus.indexer.ssl.create_default_context'), \
             patch('nexus.indexer.build_opener') as builder:
            handle = builder.return_value.open.return_value.__enter__.return_value
            handle.read.return_value = raw
            return indexer.collect(self.config_path)

    def large_response(self, text):
        value = copy.deepcopy(indexer_fixtures.response())
        value['hits']['hits'][0]['_source']['full_log'] = text
        return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

    def test_valid_indexer_response_above_one_mb_is_grouped_without_manual_import_limit(self):
        for content in ('A' * 1_100_000, '\u1ea3' * 370_000):
            with self.subTest(content_type='ascii' if content[0]=='A' else 'utf8'):
                raw = self.large_response(content)
                self.assertGreater(len(raw), MAX_TEXT_BYTES)
                self.assertLess(len(raw), indexer.MAX_RESPONSE_BYTES)
                result = self.collect_raw(raw)
                self.assertEqual(result['returned'], 1)
                self.assertEqual(result['preview']['total_events'], 1)
                self.assertEqual(result['preview']['groups'][0]['event_indexes'], [1])
                self.assertEqual(result['documents'][0]['event']['full_log'], content)

    def test_response_above_two_mb_still_has_explicit_size_error(self):
        with self.assertRaises(indexer.CollectionError) as raised:
            self.collect_raw(b'A' * (indexer.MAX_RESPONSE_BYTES + 1))
        self.assertEqual(raised.exception.code, 'response_too_large')

    def test_manual_import_retains_one_mb_limit(self):
        event = dict(indexer_fixtures.EVENT, full_log='A' * 1_100_000)
        with self.assertRaises(Invalid): inspect_events(json.dumps(event), 'alerts', 'fixture')


class HeldOutHTTPRegressionTests(unittest.TestCase):
    setUp = http_fixtures.HTTPFixes.setUp
    tearDown = http_fixtures.HTTPFixes.tearDown
    request = http_fixtures.HTTPFixes.request

    def test_held_out_tuned_run_is_accepted_through_records_api(self):
        case = dict(title='Development fixture', technique='T1059', source='fixture',
                    criteria='synthetic', environment='fixture', split='development')
        _, development = self.request('POST','/api/records',{'kind':'case','data':case})
        _, held = self.request('POST','/api/records',{'kind':'case','data':dict(case,title='Held out',split='held_out')})
        _, candidate = self.request('POST','/api/records',{'kind':'candidate','data':{
            'title':'Fixture rule','case_id':development['id'],
            'xml':'<group name="fixture"><rule id="100001" level="3"><match>fixture</match></rule></group>',
            'rationale':'synthetic','playbook':'synthetic'}})
        code, run = self.request('POST','/api/records',{'kind':'run','data':{
            'case_id':held['id'],'phase':'tuned','candidate_id':candidate['id'],
            'execution':'unknown','notes':'held-out evaluation fixture'}})
        self.assertEqual(code, 201)
        self.assertEqual(run['case_id'], held['id'])

    def test_large_valid_indexer_response_reaches_snapshot_api(self):
        config_path = Path(self.tmp.name)/'indexer.json'
        config_path.write_text(json.dumps(indexer_fixtures.CONFIG),encoding='utf-8')
        value = copy.deepcopy(indexer_fixtures.response())
        value['hits']['hits'][0]['_source']['full_log'] = 'A' * 1_100_000
        raw = json.dumps(value,separators=(',',':')).encode()
        with patch.dict(os.environ,NEXUS_INDEXER_PASSWORD='CANARY-fixture'),patch('nexus.indexer.ssl.create_default_context'),patch('nexus.indexer.build_opener') as builder:
            builder.return_value.open.return_value.__enter__.return_value.read.return_value=raw
            code, result=self.request('POST','/api/indexer/collect',{})
        self.assertEqual(code,200)
        self.assertEqual(result['preview']['total_events'],1)
        self.assertTrue(result['snapshot_id'])
