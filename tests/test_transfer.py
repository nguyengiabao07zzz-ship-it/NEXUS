import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nexus.core import Invalid
from nexus.transfer import fetch_lab_sample


EVENT = {'timestamp': '2026-11-24T21:47:00+07:00', 'agent': {'id': '001'},
         'rule': {'id': '100901'}, 'full_log': 'synthetic transfer fixture'}
TEST_TMP = Path(__file__).resolve().parents[1] / 'tmp' / 'tests'
TEST_TMP.mkdir(parents=True, exist_ok=True)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TEST_TMP)
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name) / 'missing folder' / 'imports'

    def download(self, command, **kwargs):
        self.assertTrue(self.folder.is_dir())
        self.assertEqual(kwargs['cwd'], self.folder.resolve())
        self.assertFalse(kwargs['shell'])
        self.assertTrue(command[-1].startswith('./.download-'))
        self.assertIn('StrictHostKeyChecking=yes', command)
        self.assertEqual(command[-2], 'student@192.168.157.130:nexus-alerts-sample.jsonl')
        (kwargs['cwd'] / command[-1]).write_text(json.dumps(EVENT) + '\n', encoding='utf-8')
        return SimpleNamespace(returncode=0)

    def test_missing_destination_is_created_and_existing_samples_are_preserved(self):
        with patch('nexus.transfer.subprocess.run', side_effect=self.download):
            a = fetch_lab_sample('192.168.157.130', destination_dir=self.folder)
            b = fetch_lab_sample('192.168.157.130', destination_dir=self.folder)
        self.assertNotEqual(a['file'], b['file'])
        self.assertEqual(a['total_events'], 1)
        self.assertFalse(a['external_send_allowed'])
        self.assertEqual(len(list(self.folder.glob('*.jsonl'))), 2)
        self.assertEqual(list(self.folder.glob('*.part')), [])

    def test_invalid_targets_never_start_a_process(self):
        with patch('nexus.transfer.subprocess.run') as runner:
            for args in [dict(host='-oProxyCommand=bad'), dict(host='192.168.157.130', user='student;id'),
                         dict(host='192.168.157.130', port=True), dict(host='192.168.157.130', port=0)]:
                with self.assertRaises(Invalid):
                    fetch_lab_sample(**args, destination_dir=self.folder)
            runner.assert_not_called()

    def test_transfer_failure_does_not_publish_partial_file_or_error_text(self):
        def fail(command, **kwargs):
            (kwargs['cwd'] / command[-1]).write_text('CANARY-PARTIAL', encoding='utf-8')
            return SimpleNamespace(returncode=1, stderr=b'CANARY-STDERR')
        with patch('nexus.transfer.subprocess.run', side_effect=fail), self.assertRaises(Invalid) as exc:
            fetch_lab_sample('192.168.157.130', destination_dir=self.folder)
        self.assertNotIn('CANARY', str(exc.exception))
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_timeout_and_malformed_sample_do_not_publish_files(self):
        for effect in [subprocess.TimeoutExpired(['scp'], 120),
                       lambda *args, **kwargs: SimpleNamespace(returncode=0)]:
            with patch('nexus.transfer.subprocess.run', side_effect=effect), self.assertRaises(Invalid):
                fetch_lab_sample('192.168.157.130', destination_dir=self.folder)
            self.assertEqual(list(self.folder.iterdir()), [])

    def test_interactive_password_is_left_to_terminal(self):
        with patch('nexus.transfer.subprocess.run', side_effect=self.download) as runner:
            fetch_lab_sample('192.168.157.130', destination_dir=self.folder, interactive=True)
        args, kwargs = runner.call_args
        self.assertNotIn('-B', args[0])
        self.assertFalse(kwargs['capture_output'])
        self.assertNotIn('input', kwargs)

    def test_oversized_sample_is_rejected(self):
        def large(command, **kwargs):
            (kwargs['cwd'] / command[-1]).write_bytes(b'x' * 1_000_001)
            return SimpleNamespace(returncode=0)
        with patch('nexus.transfer.subprocess.run', side_effect=large), self.assertRaises(Invalid):
            fetch_lab_sample('192.168.157.130', destination_dir=self.folder)
        self.assertEqual(list(self.folder.iterdir()), [])
