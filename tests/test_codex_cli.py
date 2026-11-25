import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nexus import codex_cli, llm
import test_analysis as fixtures
from nexus.core import Invalid
valid_analysis = fixtures.valid_analysis

CONFIG = {'provider': 'codex_cli', 'model': 'fixture-model', 'max_output_tokens': 2048}


class CodexTests(unittest.TestCase):
    def test_missing_path_discovers_registered_desktop_package(self):
        if os.name != 'nt':
            self.skipTest('Windows package discovery')
        with patch.object(codex_cli.shutil,'which',return_value=None), patch.object(codex_cli.subprocess,'run') as runner, patch.object(Path,'is_file',return_value=True):
            runner.return_value.stdout=b'C:\\Program Files\\WindowsApps\\OpenAI.Codex_fixture\r\n'
            path=codex_cli.executable()
            self.assertTrue(path.endswith('app\\resources\\codex.exe'))
            self.assertIn('Get-AppxPackage -Name OpenAI.Codex',runner.call_args.args[0][-1])
            self.assertNotIn('shell',runner.call_args.kwargs)

    def test_package_discovery_failure_stays_unavailable(self):
        with patch.object(codex_cli.shutil,'which',return_value=None), patch.object(codex_cli.subprocess,'run',side_effect=OSError()):
            self.assertIsNone(codex_cli.executable())

    def request(self):
        return llm.build_request(CONFIG, 'Fixture system', {'evidence': [{'ref': 'E1', 'content': {}}]})

    def test_environment_removes_indexer_and_api_secrets(self):
        with patch.dict(os.environ, {'PATH': 'fixture-path', 'NEXUS_INDEXER_PASSWORD': 'CANARY',
                                   'OPENAI_API_KEY': 'CANARY', 'NEXUS_OPENAI_API_KEY': 'CANARY',
                                   'CODEX_API_KEY': 'CANARY'}, clear=True):
            self.assertEqual(codex_cli.environment(), {'PATH': 'fixture-path'})

    def test_ready_requires_chatgpt_and_never_reads_auth_file(self):
        with patch.object(codex_cli, 'executable', return_value='fixture-codex'), patch.object(codex_cli.subprocess, 'run') as runner:
            for message, ready in [(b'Logged in using ChatGPT', True), (b'Logged in using an API key', False)]:
                runner.return_value = Mock(returncode=0, stdout=message, stderr=b'')
                self.assertEqual(codex_cli.readiness()['ready'], ready)
                self.assertEqual(runner.call_args.args[0][-2:], ['login', 'status'])

    def run_mock(self, event=None, answer=None, exitcode=0):
        def start(args, **kwargs):
            self.assertNotIn('shell', kwargs)
            self.assertEqual(kwargs['env'].get('NEXUS_INDEXER_PASSWORD'), None)
            self.assertIn('read-only', args)
            self.assertIn('--ignore-user-config', args)
            self.assertIn('features.shell_tool=false', args)
            self.assertIn('features.plugins=false', args)
            self.assertIn('forced_login_method="chatgpt"', args)
            self.assertIn('web_search="disabled"', args)
            self.assertEqual(args[-1], '-')
            output = Path(args[args.index('--output-last-message') + 1])
            output.write_text(json.dumps(answer or valid_analysis()), encoding='utf-8')
            events = [event] if event else [{'type':'item.completed','item':{'type':'agent_message'}}]
            events.append({'type':'turn.completed','usage':{'input_tokens':1,'output_tokens':2}})
            kwargs['stdout'].write(('\n'.join(json.dumps(value) for value in events)+'\n').encode())
            kwargs['stdout'].flush()
            return Mock(returncode=exitcode, poll=Mock(return_value=exitcode))
        with patch.object(codex_cli, 'readiness', return_value={'ready':True}), patch.object(codex_cli, 'executable', return_value='fixture-codex'), patch.object(codex_cli.subprocess, 'Popen', side_effect=start):
            return llm.call(CONFIG, self.request(), ['E1'])

    def test_sanitized_prompt_and_schema_produce_valid_result(self):
        request = self.request()
        self.assertEqual(request['schema'], llm.output_schema(['E1']))
        self.assertNotIn('max_output_tokens', request)
        result = self.run_mock()
        self.assertEqual(result['provider'], 'codex_cli')
        self.assertEqual(result['usage']['output_tokens'], 2)

    def test_nonzero_tools_and_unknown_evidence_are_rejected(self):
        for kwargs in ({'exitcode':1}, {'event':{'type':'item.started','item':{'type':'command_execution'}}},
                       {'answer':valid_analysis('E999')}):
            with self.subTest(kwargs=kwargs), self.assertRaises(llm.AIError):
                self.run_mock(**kwargs)

    def test_only_exact_disabled_code_mode_notice_is_accepted(self):
        result=self.run_mock(event={'type':'item.completed','item':{'type':'error','message':codex_cli.DISABLED_CODE_MODE_NOTICE}})
        self.assertEqual(result['provider'],'codex_cli')
        with self.assertRaises(llm.AIError):
            self.run_mock(event={'type':'item.completed','item':{'type':'error','message':'other CLI failure'}})

    def test_missing_cli_or_login_does_not_start_agent(self):
        with patch.object(codex_cli, 'readiness', return_value={'ready':False,'code':'codex_login_required'}), patch.object(codex_cli.subprocess, 'Popen') as start:
            with self.assertRaises(llm.AIError):
                llm.call(CONFIG, self.request(), ['E1'])
            start.assert_not_called()

    def test_timeout_stops_owned_process_without_retry(self):
        with patch.object(codex_cli, 'readiness', return_value={'ready':True}), patch.object(codex_cli, 'executable', return_value='fixture'), patch.object(codex_cli.subprocess, 'Popen') as start, patch.object(codex_cli.time, 'monotonic', side_effect=[0,181]), patch.object(codex_cli, 'stop') as stop:
            start.return_value.poll.return_value = None
            with self.assertRaises(llm.AIError) as raised:
                llm.call(CONFIG, self.request(), ['E1'])
            self.assertEqual(raised.exception.code, 'codex_timeout')
            start.assert_called_once()
            stop.assert_called_once_with(start.return_value)


class CodexApprovalTests(unittest.TestCase):
    setUp = fixtures.AnalysisTests.setUp
    preview = fixtures.AnalysisTests.preview
    def test_codex_still_requires_approval_and_single_use(self):
        self.path.write_text(json.dumps(CONFIG), encoding='utf-8')
        preview = self.preview()
        self.assertNotIn('CANARY', json.dumps(preview['request']))
        self.assertEqual(preview['provider'], 'codex_cli')
        with patch('nexus.codex_cli.readiness', return_value={'ready':True}), patch('nexus.codex_cli.call') as call:
            call.return_value={'analysis':valid_analysis(),'usage':{},'provider':'codex_cli'}
            with self.assertRaises(Invalid):
                self.service.run(preview['preview_id'], preview['request_sha256'], False)
            call.assert_not_called()
            self.service.run(preview['preview_id'], preview['request_sha256'], True)
            call.assert_called_once()
            with self.assertRaises(Invalid):
                self.service.run(preview['preview_id'], preview['request_sha256'], True)


class CodexHTTPTests(unittest.TestCase):
    setUp = fixtures.AnalysisHTTPTests.setUp
    tearDown = fixtures.AnalysisHTTPTests.tearDown
    request = fixtures.AnalysisHTTPTests.request

    def test_status_and_approved_run_use_codex_without_api_key(self):
        (Path(self.tmp.name)/'ai.json').write_text(json.dumps(CONFIG), encoding='utf-8')
        with patch('nexus.codex_cli.readiness', return_value={'ready':True,'code':'codex_ready'}), patch('nexus.codex_cli.call') as caller, patch('nexus.server.indexer.collect',return_value=fixtures.collection()):
            code, status = self.request('GET','/api/ai/status')
            self.assertEqual(code,200)
            self.assertEqual(status['provider'],'codex_cli')
            self.assertTrue(status['key_available'])
            self.assertIsNone(status['max_output_tokens'])
            _, collection=self.request('POST','/api/indexer/collect',{})
            _, preview=self.request('POST','/api/ai/preview',{'snapshot_id':collection['snapshot_id'],'event_indexes':[1]})
            caller.assert_not_called()
            caller.return_value={'analysis':valid_analysis(),'provider':'codex_cli','usage':{}}
            code,result=self.request('POST','/api/ai/run',{'preview_id':preview['preview_id'],'request_sha256':preview['request_sha256'],'approved':True})
            self.assertEqual(code,200)
            self.assertFalse(result['actions_executed'])
            caller.assert_called_once()
