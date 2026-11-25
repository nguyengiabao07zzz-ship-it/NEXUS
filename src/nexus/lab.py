"""Fixed, read-only lab probe. No caller-provided commands."""
import subprocess
import time

COMMAND = ('dpkg-query -W wazuh-manager wazuh-indexer wazuh-dashboard; '
           'systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard')


def probe():
    start = time.monotonic()
    try:
        result = subprocess.run(
            ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o',
             'StrictHostKeyChecking=yes', '-p', '2222', 'student@127.0.0.1', COMMAND],
            capture_output=True, text=True, timeout=15, encoding='utf-8', errors='replace')
        return {'status': 'ok' if result.returncode == 0 else 'error',
                'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
                'duration_seconds': round(time.monotonic() - start, 2),
                'scope': 'read_only_ssh_packages_and_services',
                'api_verified': False, 'indexer_query_verified': False}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'status': 'error', 'error': str(e), 'scope': 'read_only_ssh_packages_and_services'}
