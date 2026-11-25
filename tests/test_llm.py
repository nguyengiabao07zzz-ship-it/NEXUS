import copy
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from nexus import llm
from nexus.core import Invalid
from test_analysis import CONFIG, valid_analysis


def api_response():
    return {'id':'resp_fixture', 'model':'fixture-model', 'status':'completed',
            'output':[{'type':'message','content':[{'type':'output_text','text':json.dumps(valid_analysis())}]}],
            'usage':{'input_tokens':10,'output_tokens':20,'total_tokens':30}}


class LLMTests(unittest.TestCase):
    def test_windows_without_ca_imports_public_roots(self):
        with patch('nexus.llm.ssl.create_default_context') as factory, patch('nexus.llm.WINDOWS',True), patch('nexus.llm.subprocess.run') as run:
            context=factory.return_value
            context.cert_store_stats.return_value={'x509_ca':0}
            run.return_value.stdout=b'public-root-fixture'
            self.assertIs(llm.tls_context(),context)
            context.load_verify_locations.assert_called_once_with(cadata='public-root-fixture')
            self.assertIn('ReadOnly',run.call_args.args[0][-1])

    def test_existing_ca_store_does_not_launch_powershell(self):
        with patch('nexus.llm.ssl.create_default_context') as factory, patch('nexus.llm.subprocess.run') as run:
            factory.return_value.cert_store_stats.return_value={'x509_ca':1}
            llm.tls_context()
            run.assert_not_called()

    def call(self, response):
        with patch.dict(os.environ,NEXUS_OPENAI_API_KEY='CANARY-API-KEY'), patch('nexus.llm.build_opener') as builder:
            handle=builder.return_value.open.return_value.__enter__.return_value
            handle.read.return_value=json.dumps(response).encode()
            result=llm.call(CONFIG,{'store':False},['E1'])
            self.assertEqual(builder.return_value.open.call_count,1)
            request=builder.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url,'https://api.openai.com/v1/responses')
            self.assertNotIn('CANARY',request.data.decode())
            return result

    def test_completed_response_validates_and_preserves_usage(self):
        result=self.call(api_response())
        self.assertEqual(result['analysis']['findings'][0]['evidence_refs'],['E1'])
        self.assertEqual(result['usage']['total_tokens'],30)
        self.assertEqual(result['response_id'],'resp_fixture')

    def test_bad_references_and_extra_executable_fields_are_rejected(self):
        for analysis in [valid_analysis('E999'),dict(valid_analysis(),shell='execute'),
                         dict(valid_analysis(),limitations=[]),dict(valid_analysis(),summary='')]:
            with self.assertRaises(llm.AIError):
                llm.validate_analysis(analysis,['E1'])

    def test_incomplete_refusal_tool_call_and_bad_json_are_rejected(self):
        incomplete=api_response();incomplete['status']='incomplete'
        refusal=api_response();refusal['output'][0]['content']=[{'type':'refusal','refusal':'fixture'}]
        tool=api_response();tool['output']=[{'type':'function_call','name':'shell'}]
        bad=api_response();bad['output'][0]['content'][0]['text']='```not JSON```'
        for response in [incomplete,refusal,tool,bad]:
            with self.assertRaises(llm.AIError):self.call(response)

    def test_config_has_no_endpoint_or_key_override_and_no_default_model(self):
        for config in [dict(CONFIG,api_key='CANARY'),dict(CONFIG,endpoint='https://other'),
                       dict(CONFIG,provider='unknown'),dict(CONFIG,max_output_tokens=True),
                       dict(CONFIG,model='YOUR_MODEL_ID')]:
            with self.assertRaises(Invalid):llm.validate_config(config)

    def test_request_uses_structured_schema_store_false_and_no_tools(self):
        request=llm.build_request(CONFIG,'system fixture',{'evidence':[{'ref':'E1','content':{}}]})
        self.assertFalse(request['store'])
        self.assertNotIn('tools',request)
        self.assertEqual(request['max_output_tokens'],2048)
        self.assertTrue(request['text']['format']['strict'])

    def test_http_failure_never_echoes_provider_error_or_retries(self):
        with patch.dict(os.environ,NEXUS_OPENAI_API_KEY='CANARY-API-KEY'),patch('nexus.llm.build_opener') as builder:
            builder.return_value.open.side_effect=HTTPError('https://fixture',429,'CANARY-ERROR',{},io.BytesIO(b'CANARY-RAW'))
            with self.assertRaises(llm.AIError) as exc:llm.call(CONFIG,{},['E1'])
            self.assertEqual(exc.exception.code,'ai_rate_or_quota')
            self.assertNotIn('CANARY',str(exc.exception))
            builder.return_value.open.assert_called_once()

    def test_missing_key_does_not_send(self):
        with patch.dict(os.environ,{},clear=True),patch('nexus.llm.build_opener') as builder:
            with self.assertRaises(llm.AIError):llm.call(CONFIG,{},['E1'])
            builder.assert_not_called()

    def test_oversized_response_is_rejected_before_parsing(self):
        with patch.dict(os.environ,NEXUS_OPENAI_API_KEY='fixture-key'),patch('nexus.llm.build_opener') as builder:
            handle=builder.return_value.open.return_value.__enter__.return_value
            handle.read.return_value=b'x'*(llm.MAX_RESPONSE_BYTES+1)
            with self.assertRaises(llm.AIError) as exc:llm.call(CONFIG,{},['E1'])
            self.assertEqual(exc.exception.code,'ai_response_too_large')
            handle.read.assert_called_once_with(llm.MAX_RESPONSE_BYTES+1)
