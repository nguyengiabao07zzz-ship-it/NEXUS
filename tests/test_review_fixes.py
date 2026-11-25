import http.client
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nexus.core import Invalid, Store
from nexus.server import make_server, MAX_BODY
import test_core as fixtures
TEST_TMP = fixtures.TEST_TMP


class RecordFixes(unittest.TestCase):
    setUp = fixtures.WorkflowTests.setUp
    run_data = fixtures.WorkflowTests.run_data
    candidate = fixtures.WorkflowTests.candidate

    def test_r2_01_non_success_execution_only_keeps_source(self):
        lab = self.s.add('evidence', dict(label='Synthetic lab metadata', origin='lab',
                                        role='execution', content='Synthetic prevention evidence'))
        for status, label in [('blocked', 'blocked'), ('failed', 'execution_failed'), ('unknown', 'inconclusive')]:
            with self.subTest(status=status):
                self.s.add('run', self.run_data(execution=status, execution_evidence=lab['id'],
                                                observation_evidence=''))
                self.s.add('run', self.run_data(execution=status, observation_evidence=''))
                report = self.s.report()
                for source in ('lab', 'fixture'):
                    self.assertEqual(report['groups'][source]['phases']['baseline'][label], 1)
        self.assertEqual(self.s.report()['groups']['unknown']['total_runs'], 0)

    def test_r2_01_no_evidence_or_incomplete_success_stays_unknown(self):
        for status in ('blocked', 'failed', 'unknown', 'success'):
            self.s.add('run', self.run_data(execution=status, execution_evidence='', observation_evidence=''))
        self.s.add('run', self.run_data(execution='success', observation_evidence=''))
        self.assertEqual(self.s.report()['groups']['unknown']['total_runs'], 5)
        self.assertEqual(self.s.report()['groups']['lab']['total_runs'], 0)

    def test_r2_01_supplied_mixed_observation_is_not_ignored(self):
        lab = self.s.add('evidence', dict(label='Synthetic lab metadata', origin='lab',
                                        role='execution', content='Synthetic failure evidence'))
        self.s.add('run', self.run_data(execution='blocked', execution_evidence=lab['id']))
        self.assertEqual(self.s.report()['groups']['mixed']['phases']['baseline']['blocked'], 1)
        self.assertEqual(self.s.report()['groups']['lab']['total_runs'], 0)

    def test_r2_01_legacy_missing_origin_or_wrong_role_stays_unknown(self):
        with self.s.connect() as db:
            for i, evidence in enumerate([
                dict(label='legacy', content='fixture', origin='lab'),
                dict(label='wrong role', content='fixture', origin='lab', role='manager_log'),
                dict(label='unknown origin', content='fixture', origin='unknown', role='execution')]):
                evidence_id = 'legacy-exec-' + str(i)
                db.execute('INSERT INTO records VALUES (?,?,?,?)', (evidence_id, 'evidence', 'old', json.dumps(evidence)))
                run = dict(self.run_data(execution='blocked', execution_evidence=evidence_id,
                                         observation_evidence=''), outcome='blocked')
                db.execute('INSERT INTO records VALUES (?,?,?,?)', ('legacy-run-' + str(i), 'run', 'old', json.dumps(run)))
        self.assertEqual(self.s.report()['groups']['unknown']['total_runs'], 3)
    def test_f01_fixture_mixed_and_lab_are_separate(self):
        self.s.add('run',self.run_data())
        labexec=self.s.add('evidence',dict(label='LAB-like fixture metadata',origin='lab',role='execution',content='test only'))
        labobs=self.s.add('evidence',dict(label='LAB-like fixture metadata',origin='lab',role='source_log',content='test only observation'))
        self.s.add('run',self.run_data(execution_evidence=labexec['id'],observation_evidence=labobs['id']))
        self.s.add('run',self.run_data(execution_evidence=labexec['id']))
        self.s.add('run',self.run_data(execution_evidence=''))
        report=self.s.report()
        for group in ('lab','fixture','mixed','unknown'):
            self.assertEqual(report['groups'][group]['total_runs'],1)

    def test_f01_reject_duplicate_or_wrong_role(self):
        for changes in ({'observation_evidence':self.e['id']},
                        {'execution_evidence':self.observation['id'],'observation_evidence':self.e['id']}):
            with self.assertRaises(Invalid):self.s.add('run',self.run_data(**changes))

    def test_f02_exclude_without_deleting_and_persist(self):
        run=self.s.add('run',self.run_data())
        self.s.add('supersede',dict(target_id=run['id'],reason='Wrong observation',by='fixture reviewer'))
        fresh=Store(self.s.path)
        self.assertEqual(fresh.report()['groups']['fixture']['total_runs'],0)
        self.assertEqual(fresh.report()['superseded_runs'],1)
        self.assertEqual(fresh.get(run['id']),run)
        with self.assertRaises(Invalid):self.s.add('supersede',dict(target_id=run['id'],reason='again',by='fixture'))
        with self.assertRaises(Invalid):self.s.add('supersede',dict(target_id=self.e['id'],reason='wrong kind',by='fixture'))
        with self.assertRaises(Invalid):self.s.add('supersede',dict(target_id=run['id'],reason='',by='fixture'))

    def test_f05_fields_and_types_rejected_even_failed(self):
        for changes in ({'made_up_field':'value'},{'log_present':'yes','execution':'failed'},
                        {'alert_matches':123,'execution':'blocked'}, {'notes':{}},
                        {'candidate_id':'does-not-exist'}):
            with self.assertRaises(Invalid):self.s.add('run',self.run_data(**changes))
        with self.assertRaises(Invalid):self.s.add('case',dict(self.case))

    def test_f05_cross_case_candidate_and_parent(self):
        second=self.s.add('case',dict(title='Other',technique='T1059',source='fixture',criteria='fixture',environment='fixture',split='development'))
        candidate=self.candidate(case_id=second['id'])
        with self.assertRaises(Invalid):self.s.add('run',self.run_data(phase='tuned',candidate_id=candidate['id']))
        with self.assertRaises(Invalid):self.candidate(parent_id=candidate['id'])

    def test_f07_bad_records_visible_as_count_not_crash(self):
        good=self.s.add('run',self.run_data())
        with self.s.connect() as db:
            for identifier,kind,body in [('badjson','evidence','not json'),('emptyrun','run','{}'),
                                          ('list','case','[]'),('deep','evidence','['*2000+'0'+']'*2000)]:
                db.execute('INSERT INTO records VALUES (?,?,?,?)',(identifier,kind,'2026-11-12',body))
        self.assertEqual(self.s.report()['corrupt_records'],4)
        self.assertEqual(self.s.report()['active_runs'],1)
        self.assertEqual(self.s.get(good['id']),good)

    def test_f01_legacy_roleless_evidence_not_lab(self):
        legacy=dict(self.run_data(),outcome='log_without_alert')
        with self.s.connect() as db:
            db.execute('INSERT INTO records VALUES (?,?,?,?)',('old_evidence','evidence','old',json.dumps(dict(label='legacy',origin='lab',content='legacy'))))
            legacy['observation_evidence']='old_evidence'
            db.execute('INSERT INTO records VALUES (?,?,?,?)',('old_run','run','old',json.dumps(legacy)))
        self.assertEqual(self.s.report()['groups']['lab']['total_runs'],0)
        self.assertEqual(self.s.report()['groups']['unknown']['total_runs'],1)


class HTTPFixes(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=TEST_TMP)
        self.server=make_server(0,self.tmp.name)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        _,data=self.request('GET','/api/session')
        self.token=data['token']

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()

    def request(self,method,path,data=None,headers=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=15)
        h={'Content-Type':'application/json','X-Nexus-Token':getattr(self,'token','')}
        h.update(headers or {})
        body=data if isinstance(data,bytes) else (json.dumps(data).encode() if data is not None else None)
        try:
            conn.request(method,path,body,h);r=conn.getresponse();return r.status,json.loads(r.read())
        finally:conn.close()

    def test_f06_second_bind_fails(self):
        with self.assertRaises(OSError):make_server(self.server.server_port,self.tmp.name)

    def test_http_records_and_security_boundaries(self):
        code,case=self.request('POST','/api/records',{'kind':'case','data':dict(title='HTTP fixture',technique='T1059',source='fixture',criteria='fixture',environment='fixture',split='development')})
        self.assertEqual(code,201)
        code,state=self.request('GET','/api/state');self.assertEqual(state['records'][0]['id'],case['id'])
        for headers in ({'Host':'untrusted.example'}, {'X-Nexus-Token':'wrong'}, {'Origin':'https://untrusted.example'}):
            self.assertEqual(self.request('GET','/api/state',headers=headers)[0],403)
        self.assertEqual(self.request('POST','/api/records',b'{}',{'Content-Length':str(MAX_BODY+1)})[0],400)
        self.assertEqual(self.request('POST','/api/records',{'kind':'case','data':{'extra':'bad'}})[0],400)

    def test_http_case_evidence_run_supersede_roundtrip(self):
        def add(kind,data):
            status,result=self.request('POST','/api/records',{'kind':kind,'data':data})
            self.assertEqual(status,201,result)
            return result
        case=add('case',dict(title='HTTP workflow fixture',technique='T1059',source='fixture',
                            criteria='fixture',environment='fixture',split='development'))
        execution=add('evidence',dict(label='Fixture execution',content='marker',origin='fixture',role='execution'))
        observation=add('evidence',dict(label='Fixture observation',content='query result',origin='fixture',role='manager_log'))
        run=add('run',dict(case_id=case['id'],phase='baseline',execution='success',notes='fixture only',
                           execution_evidence=execution['id'],observation_evidence=observation['id'],
                           log_present=True,alert_matches=False))
        _,state=self.request('GET','/api/state')
        self.assertEqual(state['report']['groups']['fixture']['total_runs'],1)
        self.assertEqual(state['report']['groups']['lab']['total_runs'],0)
        add('supersede',dict(target_id=run['id'],reason='Fixture correction',by='test reviewer'))
        _,state=self.request('GET','/api/export')
        self.assertEqual(state['report']['active_runs'],0)
        self.assertEqual(state['report']['superseded_runs'],1)
        self.assertTrue(any(r['id']==run['id'] for r in state['records']))

    def test_f07_internal_errors_logged_without_secret(self):
        sentinel='CANARY-EXCEPTION-DO-NOT-LOG-947'
        with patch.object(Store,'add',side_effect=RuntimeError(sentinel)):
            self.assertEqual(self.request('POST','/api/records',{'kind':'case','data':{'secret':sentinel}})[0],500)
        with patch.object(Store,'report',side_effect=RuntimeError(sentinel)):
            self.assertEqual(self.request('GET','/api/state')[0],500)
        deep=b'{"text":'+b'['*2000+b'0'+b']'*2000+b'}'
        status,result=self.request('POST','/api/redact',deep)
        self.assertEqual(status,400)
        self.assertEqual(result['error'],'JSON vượt giới hạn độ sâu')
        log=(Path(self.tmp.name)/'errors.log').read_text(encoding='utf-8')
        self.assertIn('RuntimeError',log);self.assertIn('frames',log);self.assertIn('Invalid',log)
        self.assertNotIn(sentinel,log)

    def test_f07_corrupt_db_does_not_break_state(self):
        store=Store(Path(self.tmp.name)/'nexus.sqlite3')
        with store.connect() as db:
            db.execute('INSERT INTO records VALUES (?,?,?,?)',('damaged','run','old','{}'))
        status,data=self.request('GET','/api/state')
        self.assertEqual(status,200)
        self.assertEqual(data['report']['corrupt_records'],1)
        self.assertEqual(data['records'],[])
        with store.connect() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM records').fetchone()[0],1)

    def test_f11_bad_key_fails_start_without_replacing(self):
        with tempfile.TemporaryDirectory(dir=TEST_TMP) as folder:
            key=Path(folder)/'hmac.key';key.write_bytes(b'')
            with self.assertRaises(Invalid):make_server(0,folder)
            self.assertEqual(key.read_bytes(),b'')
