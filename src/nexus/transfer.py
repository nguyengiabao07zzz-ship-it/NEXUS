"""Retrieve the explicitly exported lab sample into a private local directory.

This is an on-demand sample transfer, not a continuous Wazuh collector.
Passwords stay in the user's terminal; no host keys are accepted automatically.
"""
import hashlib
import ipaddress
import re
import subprocess
import uuid
from pathlib import Path

from .core import Invalid
from .intake import inspect_events, MAX_TEXT_BYTES


def fetch_lab_sample(host, user='student', port=22, *, destination_dir=None, interactive=False):
    # Accept explicit IPv4 lab addresses only for this initial connector.
    try:
        if not isinstance(host, str):
            raise TypeError('host')
        ipaddress.IPv4Address(host)
    except (ipaddress.AddressValueError, TypeError):
        raise Invalid('Cần địa chỉ IPv4 của VM Ubuntu') from None
    if not isinstance(user, str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user):
        raise Invalid('Tên tài khoản SSH không hợp lệ')
    if type(port) is not int or not 1 <= port <= 65535:
        raise Invalid('Cổng SSH phải từ 1 đến 65535')

    folder = Path(destination_dir) if destination_dir else (
        Path(__file__).resolve().parents[2] / 'data' / 'private' / 'imports')
    # Derive paths from the code location, never from PowerShell's current folder.
    folder = folder.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    identifier = uuid.uuid4().hex
    temporary = folder / ('.download-' + identifier + '.part')
    final = folder / ('nexus-alerts-' + identifier + '.jsonl')
    options = ['-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
               '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
               '-o', 'PermitLocalCommand=no']
    if not interactive:
        options += ['-B']
    # A relative destination avoids drive-letter/path ambiguity in Windows SCP.
    command = ['scp', '-P', str(port), *options,
               f'{user}@{host}:nexus-alerts-sample.jsonl', './' + temporary.name]
    try:
        # Reserve our temporary name with restrictive POSIX permissions. Windows
        # still uses inherited ACLs; this does not claim to set Windows ACLs.
        with temporary.open('xb'):
            temporary.chmod(0o600)
        try:
            result = subprocess.run(command, cwd=folder, shell=False, timeout=120,
                                    capture_output=not interactive)
        except subprocess.TimeoutExpired:
            raise Invalid('Hết thời gian tải mẫu; file chưa được nhập') from None
        except OSError:
            raise Invalid('Không chạy được OpenSSH scp; kiểm tra cài đặt và quyền truy cập') from None
        if result.returncode != 0:
            raise Invalid('SCP chưa thành công; kiểm tra đường mạng, host key, xác thực và file mẫu trên Ubuntu')
        if temporary.stat().st_size > MAX_TEXT_BYTES:
            raise Invalid('Mẫu tải về vượt 1 MB; chưa nhập dữ liệu')
        try:
            raw = temporary.read_bytes()
            text = raw.decode('utf-8-sig')
        except UnicodeError:
            raise Invalid('Mẫu không phải UTF-8 hợp lệ') from None
        preview = inspect_events(text, 'alerts', 'lab')
        temporary.rename(final)
        return {'file': str(final), 'sha256': hashlib.sha256(raw).hexdigest(),
                'bytes': len(raw), 'total_events': preview['total_events'],
                'provenance': 'ssh_exported_sample_not_live_collector',
                'research_run_created': False, 'external_send_allowed': False}
    finally:
        temporary.unlink(missing_ok=True)
