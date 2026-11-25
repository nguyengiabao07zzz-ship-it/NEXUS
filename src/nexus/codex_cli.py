"""Local Codex CLI bridge. No auth files are read or copied by NEXUS."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

TIMEOUT_SECONDS = 180
MAX_BYTES = 256_000
DISABLED_CODE_MODE_NOTICE = ('Code Mode is unavailable because code-mode host is disabled. '
                             'Code mode will fail closed; enable `features.code_mode_host` '
                             'and install `codex-code-mode-host`.')


def executable():
    # Refuse cmd/bat launchers: the bridge never invokes a command shell.
    path = shutil.which('codex.exe' if os.name == 'nt' else 'codex')
    if path and Path(path).suffix.lower() not in ('.cmd', '.bat'):
        return path
    if os.name != 'nt':
        return None
    # Desktop and standalone PowerShell can have different PATH values. Query
    # the current user's registered package instead of guessing a version path.
    shell = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    script = ("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "
              "Get-AppxPackage -Name OpenAI.Codex | Select-Object -ExpandProperty InstallLocation")
    try:
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', script],
                                capture_output=True, timeout=10, check=True, env=environment(),
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for line in result.stdout.decode('utf-8-sig').splitlines():
            root = Path(line.strip())
            if not root.is_absolute():
                continue
            candidate = root / 'app/resources/codex.exe'
            if candidate.is_file():
                return str(candidate)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
    return None


def environment():
    # Do not pass Wazuh passwords or API credentials to the agent subprocess.
    allowed = {'PATH', 'PATHEXT', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'TEMP', 'TMP',
               'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA',
               'PROGRAMDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'CODEX_HOME',
               'SSL_CERT_FILE', 'SSL_CERT_DIR', 'LANG', 'LC_ALL'}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def options():
    return ['--ignore-user-config', '-c', 'forced_login_method="chatgpt"']


def readiness():
    path = executable()
    if not path:
        return {'ready': False, 'code': 'codex_not_found'}
    try:
        result = subprocess.run([path, '-c', 'forced_login_method="chatgpt"', 'login', 'status'],
                                capture_output=True, timeout=10, env=environment(),
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        message = (result.stdout + result.stderr).decode('utf-8', errors='replace')
        if result.returncode == 0 and 'Logged in using ChatGPT' in message:
            return {'ready': True, 'code': 'codex_ready'}
        return {'ready': False, 'code': 'codex_login_required'}
    except (OSError, subprocess.SubprocessError):
        return {'ready': False, 'code': 'codex_status_failed'}


def command(path, model, directory, schema, output):
    args = [path, 'exec', *options(), '--ephemeral', '--skip-git-repo-check',
            '--sandbox', 'read-only', '--cd', str(directory), '--json',
            '--model', model, '--output-schema', str(schema),
            '--output-last-message', str(output), '-c', 'approval_policy="never"',
            '-c', 'web_search="disabled"', '-c', 'model_reasoning_effort="low"',
            '-c', 'project_doc_max_bytes=0']
    for feature in ('shell_tool', 'unified_exec', 'apps', 'plugins', 'browser_use',
                    'browser_use_external', 'in_app_browser', 'computer_use',
                    'multi_agent', 'multi_agent_v2', 'code_mode', 'code_mode_host',
                    'goals'):
        args += ['-c', 'features.' + feature + '=false']
    args += ['-c', 'agents.enabled=false', '-']
    return args


def stop(process):
    if process.poll() is not None:
        return
    if os.name == 'nt':
        subprocess.run([str(Path(os.environ.get('SystemRoot', r'C:\Windows')) /
                             'System32/taskkill.exe'), '/PID', str(process.pid), '/T', '/F'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                       creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=10)


def call(config, payload, refs):
    from .llm import AIError, _json, validate_output
    ready = readiness()
    if not ready['ready']:
        raise AIError(ready['code'])
    # Only the reviewed prompt/schema are used, never arbitrary command options.
    with tempfile.TemporaryDirectory(prefix='nexus-codex-') as temporary:
        directory = Path(temporary)
        schema, output, transcript = [directory / name for name in
                                      ('schema.json', 'result.json', 'events.jsonl')]
        schema.write_text(json.dumps(payload['schema']), encoding='utf-8')
        prompt = directory / 'prompt.txt'
        prompt.write_text(payload['prompt'], encoding='utf-8')
        with prompt.open('rb') as source, transcript.open('wb') as destination:
            try:
                process = subprocess.Popen(command(executable(), config['model'], directory, schema, output),
                                           stdin=source, stdout=destination, stderr=subprocess.DEVNULL,
                                           cwd=directory, env=environment(),
                                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                                           start_new_session=os.name != 'nt')
            except OSError:
                raise AIError('codex_start_failed') from None
            try:
                deadline = time.monotonic() + TIMEOUT_SECONDS
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise AIError('codex_timeout')
                    if transcript.stat().st_size > MAX_BYTES or (output.exists() and output.stat().st_size > MAX_BYTES):
                        raise AIError('ai_response_too_large')
                    time.sleep(0.1)
            finally:
                stop(process)
        if transcript.stat().st_size > MAX_BYTES:
            raise AIError('ai_response_too_large')
        if process.returncode != 0:
            raise AIError('codex_run_failed')
        try:
            usage, completed = {}, False
            for line in transcript.read_text(encoding='utf-8').splitlines():
                event = _json(line)
                kind = event.get('type')
                if kind in ('turn.failed', 'error'):
                    raise AIError('codex_run_failed')
                if kind in ('item.started', 'item.updated', 'item.completed'):
                    if (event['item']['type'] == 'error'
                            and event['item'].get('message') == DISABLED_CODE_MODE_NOTICE):
                        # Expected diagnostic confirming that code execution is
                        # disabled. It is not a tool invocation or model output.
                        continue
                    if event['item']['type'] not in ('agent_message', 'reasoning'):
                        raise AIError('codex_unexpected_tool')
                if kind == 'turn.completed':
                    completed = True
                    usage = {key: number for key, number in event.get('usage', {}).items()
                             if key in ('input_tokens', 'output_tokens', 'cached_input_tokens')
                             and type(number) is int and number >= 0}
            if not completed or not output.is_file():
                raise AIError('codex_run_failed')
            if output.stat().st_size > MAX_BYTES:
                raise AIError('ai_response_too_large')
            result_key,analysis = validate_output(_json(output.read_text(encoding='utf-8')), refs,payload)
        except (OSError, UnicodeError, ValueError, KeyError, TypeError, AttributeError):
            raise AIError('ai_invalid_output') from None
        return {result_key: analysis, 'provider': 'codex_cli', 'model': config['model'],
                'response_model': None, 'response_id': None, 'usage': usage,
                'execution_mode': 'codex_cli_chatgpt'}
