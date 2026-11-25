import json
import sqlite3
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nexus.core import Invalid, Store, redact
from nexus.server import make_server

TEST_TMP = Path(__file__).resolve().parents[1] / 'tmp' / 'tests'
TEST_TMP.mkdir(parents=True, exist_ok=True)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TEST_TMP)
        self.addCleanup(self.tmp.cleanup)
        self.s = Store(Path(self.tmp.name) / 'db.sqlite3')
        self.case = self.s.add('case',dict(title='Fixture case', technique='T1059', source='fixture only',
                                         criteria='fixture criteria', environment='fixture env',split='development'))
        self.e = self.s.add('evidence',dict(label='Fixture execution',origin='fixture',role='execution',content='synthetic execution'))
        self.observation = self.s.add('evidence',dict(label='Fixture observation',origin='fixture',role='manager_log',content='synthetic observation'))

    def run_data(self, **changes):
        data=dict(case_id=self.case['id'],phase='baseline',execution='success',notes='synthetic',
                  execution_evidence=self.e['id'],observation_evidence=self.observation['id'],
                  log_present=True,alert_matches=False)
        return dict(data, **changes)

    def candidate(self, **changes):
        return self.s.add('candidate',dict(dict(title='Fixture candidate',case_id=self.case['id'],
            xml='<group name="fixture"><rule id="100001" level="3"><match>fixture</match></rule></group>',
            rationale='synthetic',playbook='fixture only'),**changes))

    def test_excluded_runs_never_become_misses(self):
        for execution, expected in [('failed','execution_failed'),('blocked','blocked'),('unknown','inconclusive')]:
            self.assertEqual(self.s.add('run',self.run_data(execution=execution))['outcome'], expected)
        self.assertEqual(self.s.add('run',self.run_data(execution_evidence=''))['outcome'],'inconclusive')
        self.assertEqual(self.s.add('run',self.run_data(log_present=None))['outcome'],'inconclusive')

    def test_classification_requires_observation(self):
        self.assertEqual(self.s.add('run',self.run_data())['outcome'],'log_without_alert')
        self.assertEqual(self.s.add('run',self.run_data(log_present=False))['outcome'],'no_log')
        self.assertEqual(self.s.add('run',self.run_data(alert_matches=True))['outcome'],'detected')
        with self.assertRaises(Invalid):
            self.s.add('run',self.run_data(log_present=False,alert_matches=True))

    def test_evidence_reference_must_exist(self):
        with self.assertRaises(Invalid):
            self.s.add('run', self.run_data(execution_evidence='missing'))
        with self.assertRaises(Invalid):
            self.s.add('run', self.run_data(phase='tuned'))

    def test_candidates_and_records_are_immutable(self):
        c=self.candidate()
        self.assertEqual(c['validation'],'xml_well_formed_only')
        newer=self.candidate(parent_id=c['id'],xml=c['xml'].replace('level="3"','level="5"'))
        self.assertNotEqual(c['sha256'],newer['sha256'])
        with self.s.connect() as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('UPDATE records SET body=? WHERE id=?',('{}',c['id']))
        with self.assertRaises(Invalid): self.candidate(xml='<!DOCTYPE x><group/>')

    def test_no_premature_approval(self):
        c=self.candidate()
        with self.assertRaises(Invalid):
            self.s.add('review',dict(candidate_id=c['id'],reviewer='tester',decision='approve',notes='fixture'))

    def test_candidate_cannot_be_created_from_held_out_case(self):
        held = self.s.add('case', dict(title='Held out fixture', technique='T1059', source='fixture',
                                      criteria='fixture', environment='fixture', split='held_out'))
        with self.assertRaises(Invalid):
            self.candidate(case_id=held['id'])
        self.assertEqual(self.s.list('candidate'), [])

    def test_counts_do_not_claim_technique_coverage(self):
        self.s.add('run',self.run_data(execution='failed'))
        self.s.add('run',self.run_data())
        report=self.s.report()
        self.assertEqual(report['groups']['fixture']['phases']['baseline']['execution_failed'],1)
        self.assertEqual(report['groups']['fixture']['phases']['baseline']['log_without_alert'],1)
        self.assertEqual(report['groups']['lab']['total_runs'],0)
        self.assertIsNone(report['technique_coverage'])

    def test_hmac_preview_is_stable_and_never_send_authorization(self):
        raw=json.dumps({'password':'CANARY-PW-793','user':'alice@example.org','sourceip':'10.2.3.4','destinationip':'2001:db8::1'})
        a=redact(raw,b'a'*32);b=redact(raw,b'a'*32);c=redact(raw,b'b'*32)
        self.assertEqual(a,b);self.assertNotEqual(a['preview'],c['preview'])
        for value in ('CANARY-PW-793', 'alice@example.org','10.2.3.4','2001:db8::1'):
            self.assertNotIn(value,json.dumps(a))
        self.assertFalse(a['external_send_allowed'])
        with self.assertRaises(Invalid):redact(raw,b'short')


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=TEST_TMP)
        self.server=make_server(0,self.tmp.name)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()

    def test_http_roundtrip_and_origin_protection(self):
        with urllib.request.urlopen(self.base+'/') as r:
            self.assertIn(b'NEXUS',r.read());self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy'])
        with urllib.request.urlopen(self.base+'/api/session') as r:token=json.load(r)['token']
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(self.base+'/api/state')
        self.assertEqual(error.exception.code,403)
        req=urllib.request.Request(self.base+'/api/state',headers={'X-Nexus-Token':token})
        with urllib.request.urlopen(req) as r:self.assertEqual(json.load(r)['records'],[])
        req=urllib.request.Request(self.base+'/api/redact',data=json.dumps({'text':'{"sourceip":"10.1.2.3"}'}).encode(),
            headers={'X-Nexus-Token':token,'Content-Type':'application/json'})
        with urllib.request.urlopen(req) as r:self.assertNotIn('10.1.2.3',json.dumps(json.load(r)))
        req.add_header('Origin','https://untrusted.example')
        with self.assertRaises(urllib.error.HTTPError) as error:urllib.request.urlopen(req)
        self.assertEqual(error.exception.code,403)


if __name__=='__main__':unittest.main()
