import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
import zipfile
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from nexus import context,rules,llm,lab_helper,indexer
from nexus.bundle import build_bundle
from nexus.core import Store,Invalid
from nexus.monitor import Monitor
import test_analysis as fixtures

XML='<group name="nexus_lab,"><rule id="100901" level="7"><decoded_as>json</decoded_as><field name="event.action" type="pcre2">^fixture_failed$</field><description>NEXUS synthetic fixture</description></rule></group>'


def draft():
    return {'status':'proposed','title':'Synthetic rule','xml':XML,'rationale':'Synthetic fixture only',
            'evidence_refs':['E1'],'assumptions':['Decoder json must exist.'],
            'benign_tests':['A different action must not trigger this candidate.'],
            'limitations':['Not validated on a Wazuh manager.']}


class ContextTests(unittest.TestCase):
    def test_default_is_structured_without_raw_text(self):
        event={'full_log':'Failed password for CANARYUSER from 192.168.1.1','rule':{'description':'Private CANARYDESC','mitre':{'id':['T1110','CANARY']}}}
        extra,flags=context.supplement(event,b'a'*32)
        self.assertNotIn('CANARY',json.dumps(extra))
        self.assertEqual(extra['mitre_ids'],['T1110'])
        self.assertIn('authentication_failure',extra['local_pattern_signals'])
        self.assertIn('free_text_not_selected',flags)

    def test_opt_in_text_preserves_signal_and_masks_identifiers(self):
        event={'agent':{'name':'CANARYHOST'},'data':{'srcuser':'CANARYUSER'},'decoder':{'name':'sshd'},
               'full_log':'CANARYHOST sshd: Failed password for CANARYUSER from 192.168.1.1 port 2222',
               'rule':{'description':'Authentication failure on CANARYHOST'}}
        result,flags=context.supplement(event,b'a'*32,True)
        text=json.dumps(result)
        for private in ('CANARYHOST','CANARYUSER','192.168.1.1'):self.assertNotIn(private,text)
        self.assertIn('Failed password',text)
        self.assertTrue(flags)

    def test_secrets_block_entire_free_text_not_echoed(self):
        for text in ('password=CANARYSECRET','Authorization: Bearer CANARYSECRET','sk-'+('a'*60)):
            result,_=context.supplement({'full_log':text},b'a'*32,True)
            self.assertEqual(result['event_excerpt'],'[BLOCKED_POSSIBLE_SECRET]')

    def test_ip_pseudonym_matches_structured_policy(self):
        value=fixtures.project_event({'data':{'srcip':'192.0.2.1'},'full_log':'source 192.0.2.1'},b'a'*32,True)
        content=value['content']
        self.assertIn(content['data']['srcip'],content['analysis_context']['event_excerpt'])


class RuleTests(unittest.TestCase):
    def test_subset_and_bundle_hash(self):
        validation=rules.validate_xml(XML)
        self.assertEqual(validation['rule_id'],100901)
        candidate={'id':'a'*32,'case_id':'b'*32,'title':'Fixture','xml':XML}
        with zipfile.ZipFile(io.BytesIO(build_bundle(candidate))) as archive:
            self.assertEqual(set(archive.namelist()),{'nexus_rule.xml','manifest.json','README.txt','lab_helper.py'})
            self.assertEqual(json.loads(archive.read('manifest.json'))['sha256'],validation['sha256'])

    def test_unsafe_xml_and_pseudonym_conditions_are_rejected(self):
        variants=[XML.replace('level="7"','level="0"'),XML.replace('100901','5710'),
                  XML.replace('id="100901"','id="100901" overwrite="yes"'),
                  XML.replace('<decoded_as>json</decoded_as>',''),XML.replace('fixture_failed','[IP_abcdef]'),
                  '<!DOCTYPE group>'+XML,XML.replace('<description>','<unknown>'),
                  XML.replace('type="pcre2"','type="unsafe"')]
        for xml in variants:
            with self.subTest(xml=xml),self.assertRaises(Invalid):rules.validate_xml(xml)

    def test_model_draft_requires_valid_refs_and_no_xml_when_insufficient(self):
        self.assertEqual(rules.validate_draft(draft(),['E1'])['status'],'proposed')
        bad=draft();bad['evidence_refs']=['E999']
        with self.assertRaises(llm.AIError):rules.validate_draft(bad,['E1'])
        bad=draft();bad['status']='insufficient_context'
        with self.assertRaises(llm.AIError):rules.validate_draft(bad,['E1'])


class HistoryDraftTests(unittest.TestCase):
    setUp=fixtures.AnalysisTests.setUp

    def setup_case(self,split='development'):
        store=Store(self.root/'store.sqlite3');self.service.store=store
        case=store.add('case',{'title':'Fixture','technique':'T1110','source':'synthetic','criteria':'fixture','environment':'fixture','split':split})
        return case

    def test_held_out_rejected_before_model(self):
        case=self.setup_case('held_out')
        with self.assertRaises(Invalid):self.service.prepare(self.snapshot,[1],purpose='rule_draft',case_id=case['id'])

    def test_draft_preview_approval_history_and_idempotent_save(self):
        case=self.setup_case()
        preview=self.service.prepare(self.snapshot,[1],purpose='rule_draft',case_id=case['id'])
        self.assertEqual(preview['request']['text']['format']['name'],'nexus_rule_draft')
        self.assertEqual(self.service.history()['total'],0)
        with patch('nexus.llm.key_available',return_value=True),patch('nexus.llm.call',return_value={'draft':draft(),'usage':{},'provider':'openai'}):
            result=self.service.run(preview['preview_id'],preview['request_sha256'],True)
        self.assertEqual(self.service.history()['total'],1)
        detail=self.service.detail(result['request_id'])
        self.assertEqual(detail['status'],'complete')
        self.assertNotIn('request',detail)
        with self.assertRaises(Invalid):self.service.save_candidate(result['request_id'],False)
        candidate=self.service.save_candidate(result['request_id'],True)
        self.assertEqual(candidate['id'],self.service.save_candidate(result['request_id'],True)['id'])
        self.assertEqual(len(self.service.store.list('candidate')),1)

    def test_history_rejects_traversal_and_retains_errors(self):
        for identifier in ('../ai.json','x'*32,'a/../'+'b'*32):
            with self.assertRaises(Invalid):self.service.detail(identifier)
        preview=self.service.prepare(self.snapshot,[1])
        with patch('nexus.llm.key_available',return_value=True),patch('nexus.llm.call',side_effect=llm.AIError('codex_timeout')):
            with self.assertRaises(llm.AIError):self.service.run(preview['preview_id'],preview['request_sha256'],True)
        self.assertEqual(self.service.history()['items'][0]['error_code'],'codex_timeout')


class MonitorTests(unittest.TestCase):
    def test_repeated_collection_counts_ids_once_and_never_calls_ai(self):
        analyses=Mock();analyses.remember.return_value='fixture-snapshot'
        monitor=Monitor('fixture-config',analyses)
        collection=fixtures.collection();collection.update(returned=1,total_matching=2)
        with patch('nexus.monitor.indexer.collect',return_value=collection),patch('nexus.llm.call') as call:
            monitor.cycle({});monitor.cycle({});call.assert_not_called()
        self.assertEqual(monitor.status()['cycles'],2)
        self.assertEqual(monitor.status()['new_documents'],1)
        self.assertEqual(monitor.latest()['snapshot_id'],'fixture-snapshot')
        with patch('nexus.monitor.indexer.collect',side_effect=indexer.CollectionError('network_error')):monitor.cycle({})
        self.assertEqual(monitor.status()['cycles'],2)
        self.assertEqual(monitor.status()['error_code'],'network_error')

    def test_invalid_interval_query_and_empty_latest(self):
        monitor=Monitor('fixture',Mock())
        for interval in (0,1,29,3601,True):
            with self.assertRaises(Invalid):monitor.start({},interval)
        with self.assertRaises(Invalid):monitor.start({'endpoint':'untrusted'},60)
        with self.assertRaises(Invalid):monitor.latest()


class LabHelperTests(unittest.TestCase):
    def setUp(self):
        base=Path(__file__).resolve().parents[1]/'tmp/tests';base.mkdir(parents=True,exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=base);self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'etc/rules').mkdir(parents=True);(self.root/'ruleset/rules').mkdir(parents=True)
        self.manifest={'candidate_id':'a'*32,**rules.validate_xml(XML)}
        self.root_patch=patch.object(lab_helper,'ROOT',self.root);self.root_patch.start();self.addCleanup(self.root_patch.stop)
        self.group_patch=patch.object(lab_helper,'grp',Mock(getgrnam=Mock(return_value=Mock(gr_gid=0))));self.group_patch.start();self.addCleanup(self.group_patch.stop)
        self.chown=patch.object(lab_helper.os,'chown',create=True);self.chown.start();self.addCleanup(self.chown.stop)

    def command(self):return patch.object(lab_helper,'command',return_value={'returncode':0,'output':'synthetic mock','argv':[]})

    def test_stage_checks_config_does_not_restart_and_rollback_is_exact(self):
        with self.command() as run:
            lab_helper.stage(self.manifest,XML.encode());run.assert_called_once_with([self.root/'bin/wazuh-analysisd','-t'])
            lab_helper.rollback(self.manifest)
        self.assertFalse(lab_helper.target(self.manifest).exists())
        with self.command(),self.assertRaises(ValueError):lab_helper.stage(self.manifest,XML.encode())

    def test_collision_and_failed_load_never_leave_candidate(self):
        existing=self.root/'etc/rules/existing.xml';existing.write_text(XML)
        with self.assertRaises(ValueError):lab_helper.stage(self.manifest,XML.encode())
        existing.unlink()
        with patch.object(lab_helper,'command',return_value={'returncode':1,'output':'fixture invalid'}),self.assertRaises(ValueError):lab_helper.stage(self.manifest,XML.encode())
        self.assertFalse(lab_helper.target(self.manifest).exists())

    def test_numeric_padded_id_collision_is_rejected(self):
        (self.root/'etc/rules/existing.xml').write_text(XML.replace('100901','0100901'))
        with self.command() as run,self.assertRaises(ValueError):lab_helper.stage(self.manifest,XML.encode())
        run.assert_not_called()

    def test_cli_rejects_privileged_operations_outside_linux(self):
        with patch.object(lab_helper.sys,'argv',['lab_helper.py','stage','--confirm-lab']),patch.object(lab_helper.sys,'platform','win32'),patch.object(lab_helper,'bundle',return_value=(self.manifest,XML.encode())),patch.object(lab_helper,'stage') as stage,patch('sys.stderr',new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as error:lab_helper.main()
            self.assertEqual(error.exception.code,1)
            stage.assert_not_called()

    def test_activation_requires_latest_passing_tests_and_rolls_back_failure(self):
        with self.command():lab_helper.stage(self.manifest,XML.encode())
        with self.command(),self.assertRaises(ValueError):lab_helper.activate(self.manifest)
        state=lab_helper.require_target(self.manifest)
        state['checks']=[{'kind':kind,'result':'pass','candidate_sha256':self.manifest['sha256']} for kind in ('attack','benign','regression')]
        state['checks'].append({'kind':'benign','result':'failed_or_error','candidate_sha256':self.manifest['sha256']})
        lab_helper.write_state(self.manifest,state)
        with self.command(),self.assertRaises(ValueError):lab_helper.activate(self.manifest)
        state['checks'].pop();lab_helper.write_state(self.manifest,state)
        with patch.object(lab_helper,'command',side_effect=[{'returncode':0},{'returncode':1},{'returncode':1},{'returncode':0}]),self.assertRaises(ValueError):lab_helper.activate(self.manifest)
        self.assertFalse(lab_helper.target(self.manifest).exists())

    def test_changed_target_and_multi_line_sample_rejected(self):
        with self.command():lab_helper.stage(self.manifest,XML.encode())
        sample=self.root/'sample.txt';sample.write_text('fixture\nsecond line')
        with self.assertRaises(ValueError):lab_helper.logtest(self.manifest,sample,'json',100901,7,'attack')
        lab_helper.target(self.manifest).write_text('changed')
        with self.assertRaises(ValueError):lab_helper.rollback(self.manifest)


class LabHTTPTests(unittest.TestCase):
    setUp=fixtures.AnalysisHTTPTests.setUp
    tearDown=fixtures.AnalysisHTTPTests.tearDown
    request=fixtures.AnalysisHTTPTests.request

    def test_rule_flow_and_history_are_local_authenticated_and_held_out_blocked(self):
        (Path(self.tmp.name)/'ai.json').write_text(json.dumps(fixtures.CONFIG),encoding='utf-8')
        case_data={'title':'Fixture','technique':'T1110','source':'synthetic','criteria':'fixture','environment':'fixture','split':'development'}
        _,case=self.request('POST','/api/records',{'kind':'case','data':case_data})
        with patch('nexus.server.indexer.collect',return_value=fixtures.collection()):_,collection=self.request('POST','/api/indexer/collect',{})
        payload={'snapshot_id':collection['snapshot_id'],'event_indexes':[1],'purpose':'rule_draft','case_id':case['id'],'include_text':True}
        code,preview=self.request('POST','/api/ai/preview',payload);self.assertEqual(code,200)
        with patch('nexus.llm.key_available',return_value=True),patch('nexus.llm.call',return_value={'draft':draft(),'usage':{}}):
            code,result=self.request('POST','/api/ai/run',{'preview_id':preview['preview_id'],'request_sha256':preview['request_sha256'],'approved':True})
        self.assertEqual(code,200)
        self.assertEqual(self.request('GET','/api/ai/history')[1]['total'],1)
        self.assertEqual(self.request('GET','/api/ai/history',headers={'X-Nexus-Token':'wrong'})[0],403)
        code,candidate=self.request('POST','/api/ai/save-candidate',{'request_id':result['request_id'],'confirmed':True})
        self.assertEqual(code,201)
        self.assertEqual(candidate['xml'],XML)
        self.assertEqual(self.request('GET','/api/ai/history/not-valid')[0],400)
        _,held=self.request('POST','/api/records',{'kind':'case','data':dict(case_data,split='held_out')})
        self.assertEqual(self.request('POST','/api/ai/preview',dict(payload,case_id=held['id']))[0],400)
        self.assertFalse(self.request('GET','/api/monitor/status')[1]['automatic_ai'])
