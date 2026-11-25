import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from nexus.core import Invalid, redact


class CanaryTests(unittest.TestCase):
    def preview(self,value):return redact(json.dumps(value),b'a'*32)

    def test_nonstandard_known_field_names_do_not_echo_private_suffix(self):
        for field in ('user客户甲', 'name秘密', 'host\u200b', 'user@'):
            with self.subTest(field=field):
                result = self.preview({field: 'CANARY-FIELD-VALUE'})
                serialized = json.dumps(result, ensure_ascii=False)
                self.assertNotIn(field, serialized)
                self.assertNotIn('CANARY-FIELD-VALUE', serialized)
                self.assertIn('nonstandard_field_name', result['review_flags'])

    def test_r2_02_full_wazuh_shape_documents_preserved_and_lost_fields(self):
        path = Path(__file__).parent / 'fixtures' / 'wazuh_sysmon_process_create.synthetic.json'
        source = json.loads(path.read_text(encoding='utf-8'))
        result = self.preview(source)
        p = result['preview']
        self.assertEqual(p['rule']['id'], source['rule']['id'])
        self.assertEqual(p['rule']['level'], 3)
        self.assertEqual(p['decoder']['name'], 'windows_eventchannel')
        system = p['data']['win']['system']
        event = p['data']['win']['eventdata']
        for field in ('providerName', 'eventID', 'channel', 'systemTime', 'processID', 'eventRecordID'):
            self.assertEqual(system[field], source['data']['win']['system'][field])
        for field in ('utcTime', 'processId', 'parentProcessId', 'parentImage'):
            self.assertEqual(event[field], source['data']['win']['eventdata'][field])
        self.assertTrue(system['computer'].startswith('[IDENTITY_'))
        self.assertTrue(p['agent']['ip'].startswith('[IP_'))
        self.assertTrue(event['user'].startswith('[IDENTITY_'))
        # Current limitations are explicit characterization, not desired release criteria.
        self.assertEqual(p['timestamp'], '[BLOCKED]')
        self.assertEqual(system['version'], '[BLOCKED]')
        self.assertTrue(event['image'].startswith('[PATH_'))
        self.assertEqual(event['commandLine'], '[BLOCKED]')
        self.assertNotIn('description', p['rule'])
        self.assertNotIn('groups', p['rule'])
        self.assertNotIn('mitre', p['rule'])
        for unknown in ('originalFileName', 'hashes', 'integrityLevel', 'ruleName'):
            self.assertNotIn(unknown, event)
        serialized = json.dumps(result)
        self.assertNotIn('CANARY-', serialized)
        self.assertNotIn('CANARY PERSON', serialized)
        self.assertFalse(result['external_send_allowed'])
        self.assertIn('free_text_commandline', result['review_flags'])

    def test_bearer_json_nested_unknown_canaries_never_returned(self):
        canaries=['canary-Bearer-z921','canary-pwd-z922','canary-unlabeled-z923',
                  'canary-user-z924','canary-host-z925','canary-linux-z926','canary-key-z927']
        payload={'Authorization':'Bearer '+canaries[0],'data':{'win':{'eventdata':{
            'password':canaries[1],'Unknown':{'nested':canaries[2]},'User':canaries[3],
            'Computer':canaries[4],'Path':'/home/'+canaries[5]+'/id_rsa',canaries[6]:'secret'}}}}
        result=self.preview(payload);serialized=json.dumps(result)
        for secret in canaries:self.assertNotIn(secret,serialized)
        self.assertIn('unknown_field',result['review_flags'])
        self.assertFalse(result['external_send_allowed'])

    def test_structural_detection_features_preserved(self):
        stamp='2026-11-12 10:23:45'
        values={'timestamp':stamp,'eventid':'1','version':'4.14.9.1',
                'Image':r'C:\Windows\System32\cmd.exe','CommandLine':'cmd /c whoami',
                'mac':'08:00:27:aa:bb:cc','destinationip':'2001:db8::1'}
        p=self.preview(values)['preview']
        for name in ('timestamp','eventid','version','Image','CommandLine'):self.assertEqual(p[name],values[name])
        self.assertTrue(p['mac'].startswith('[MAC_'));self.assertTrue(p['destinationip'].startswith('[IP_'))

    def test_user_path_with_spaces_and_unknown_commandline(self):
        secret='CANARY PERSON 947'
        p=self.preview({'Image':'C:\\Users\\'+secret+'\\AppData\\Local\\cmd.exe',
                        'CommandLine':'cmd /c echo CANARY-ARG-948'})
        self.assertNotIn(secret,json.dumps(p));self.assertNotIn('CANARY-ARG-948',json.dumps(p))
        self.assertTrue(p['preview']['Image'].endswith('cmd.exe'))
        self.assertEqual(p['preview']['CommandLine'],'[BLOCKED]')

    def test_secret_array_and_free_text_blocked(self):
        for data in ({'password':['CANARY-X-948']},{'event':['CANARY-X-948']},
                     {'event':{'description':'Bearer CANARY-X-948'}},
                     {'CommandLine':'Authorization: Bearer CANARY-X-948'}):
            self.assertNotIn('CANARY-X-948',json.dumps(self.preview(data)))
        with self.assertRaises(Invalid):redact('Authorization: Bearer CANARY-X-948',b'a'*32)

    def test_duplicate_keys_and_invalid_json_rejected(self):
        for raw in ('{"password":"canary","password":"second"}','{"id":NaN}','null','"raw"'):
            with self.assertRaises(Invalid):redact(raw,b'a'*32)

    def test_key_id_consistency_and_domain_separation(self):
        a=self.preview({'user':'same','hostname':'same','sourceip':'10.0.0.1'})
        b=self.preview({'user':'same','hostname':'same','sourceip':'10.0.0.1'})
        c=redact('{"user":"same"}',b'b'*32)
        self.assertEqual(a,b);self.assertNotEqual(a['key_id'],c['key_id'])
        self.assertEqual(len(a['key_id']),16)

    def test_deep_input_blocked_without_original(self):
        nested={'unknown':'CANARY-DEEP-949'}
        for _ in range(40):nested={'data':nested}
        result=self.preview(nested)
        self.assertIn('depth_limit',result['review_flags'])
        self.assertNotIn('CANARY-DEEP-949',json.dumps(result))
