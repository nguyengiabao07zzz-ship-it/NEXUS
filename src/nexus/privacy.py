"""Fail-closed, field-aware JSON preview. No outbound transport or send approval."""
import hashlib
import hmac
import ipaddress
import json
import re
from datetime import datetime

POLICY_VERSION = 'json-fields-v1.1'
CONTAINERS = {'event', 'data', 'win', 'system', 'eventdata', 'agent', 'manager', 'rule',
              'decoder', 'process', 'network', 'source', 'destination', 'host', 'user'}
SECRET = re.compile(r'password|passwd|pwd|secret|token|authorization|apikey|privatekey|cookie|credential', re.I)
IDENTIFIERS = {'user', 'username', 'targetusername', 'subjectusername', 'hostname', 'computer',
               'domain', 'targetdomainname', 'subjectdomainname', 'email', 'sid', 'usersid',
               'processguid', 'parentprocessguid', 'targetusersid', 'subjectusersid'}
IPS = {'ip', 'srcip', 'dstip', 'sourceip', 'destinationip', 'ipaddress'}
NUMBERS = {'id', 'eventid', 'eventrecordid', 'processid', 'parentprocessid', 'pid', 'level',
           'sourceport', 'destinationport', 'srcport', 'dstport', 'firedtimes'}
SYSTEM_EXES = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'wscript.exe', 'cscript.exe',
               'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'schtasks.exe', 'svchost.exe',
               'dllhost.exe', 'conhost.exe', 'lsass.exe', 'services.exe', 'explorer.exe', 'reg.exe'}
SAFE_NAMES = {'Microsoft-Windows-Sysmon', 'Microsoft-Windows-Sysmon/Operational', 'Security',
              'System', 'Application', 'sshd', 'sysmon', 'json', 'windows_eventchannel', 'win',
              'TCP', 'UDP', 'tcp', 'udp', 'IPv4', 'IPv6', *SYSTEM_EXES}


def redact(text, key):
    from .core import Invalid, load_json_bounded
    if not isinstance(key, bytes) or len(key) < 32:
        raise Invalid('Khóa HMAC cần ít nhất 32 byte')
    if not isinstance(text, str):
        raise Invalid('Cần chuỗi JSON')

    def unique_pairs(pairs):
        out = {}
        for name, value in pairs:
            if name in out:
                raise Invalid('Không nhận JSON trùng tên trường')
            out[name] = value
        return out

    try:
        source = load_json_bounded(text, object_pairs_hook=unique_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(Invalid('JSON number không hợp lệ')))
    except (ValueError, RecursionError):
        raise Invalid('Chỉ nhận JSON object/array hợp lệ; không nhận log văn bản phẳng') from None
    if not isinstance(source, (dict, list)):
        raise Invalid('Cần JSON object hoặc array')
    counts, flags = {}, set()

    def pseudonym(label, value):
        counts[label] = counts.get(label, 0) + 1
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        digest = hmac.new(key, (label + '\0' + raw).encode(), hashlib.sha256).hexdigest()[:24]
        return f'[{label}_{digest}]'

    def block(reason):
        counts['BLOCKED'] = counts.get('BLOCKED', 0) + 1
        flags.add(reason)
        return '[BLOCKED]'

    def path_preview(value):
        if not isinstance(value, str): return block('path_type')
        # Preserve only known system executables; path identities never pass through.
        normalized = value.replace('/', '\\')
        if re.fullmatch(r'(?i)C:\\Windows\\(?:System32|SysWOW64)\\[\w.-]+', normalized):
            if normalized.rsplit('\\', 1)[-1].lower() in SYSTEM_EXES:
                return value
        if re.match(r'(?i)^[A-Z]:\\Users\\[^\\]+\\', normalized):
            parts = normalized.split('\\')
            allowed_dirs = {'appdata', 'roaming', 'local', 'microsoft', 'windows', 'temp', 'desktop', 'documents'}
            processed = [parts[0], 'Users', pseudonym('USER', parts[2])]
            for index, part in enumerate(parts[3:], start=3):
                if part.lower() in allowed_dirs or (index == len(parts)-1 and part.lower() in SYSTEM_EXES):
                    processed.append(part)
                else:
                    processed.append(pseudonym('PATH', part))
            return '\\'.join(processed)
        return pseudonym('PATH', value)

    def field(name, value, depth):
        if depth > 32: return block('depth_limit')
        normal = re.sub(r'[^a-z0-9]', '', name.lower())
        if SECRET.search(normal): return '[REMOVED_SECRET]'
        if normal in CONTAINERS and isinstance(value, (dict, list)):
            return walk(value, depth + 1)
        if normal in IDENTIFIERS or (normal == 'name' and isinstance(value, str) and value not in SAFE_NAMES):
            return pseudonym('IDENTITY', value)
        if normal in IPS:
            if not isinstance(value, str): return block('invalid_ip_field')
            try: ipaddress.ip_address(value)
            except (ValueError, TypeError): return block('invalid_ip_field')
            return pseudonym('IP', value)
        if normal in ('mac', 'macaddress'):
            if isinstance(value, str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', value):
                return pseudonym('MAC', value)
            return block('invalid_mac_field')
        if normal in NUMBERS:
            if type(value) is int and 0 <= value <= 2**64-1: return value
            if isinstance(value, str) and re.fullmatch(r'\d{1,20}', value): return value
            return block('invalid_numeric_field')
        if normal in ('timestamp', 'utctime', 'timecreated', 'systemtime'):
            if isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)?', value):
                try: datetime.fromisoformat(value.replace('Z', '+00:00'))
                except ValueError: return block('invalid_timestamp')
                return value
            return block('invalid_timestamp')
        if normal in ('version', 'productversion'):
            if isinstance(value, str) and re.fullmatch(r'\d+(?:\.\d+){1,3}', value): return value
            return block('invalid_version')
        if normal in ('image', 'parentimage', 'executable', 'path', 'targetfilename'):
            return path_preview(value)
        if normal in ('commandline', 'parentcommandline'):
            if isinstance(value, str) and re.fullmatch(r'(?i)(?:cmd(?:\.exe)? /c )?whoami(?:\.exe)?(?: /priv)?', value):
                return value
            return block('free_text_commandline')
        if normal in ('name', 'providername', 'channel', 'protocol', 'programname'):
            return value if isinstance(value, str) and value in SAFE_NAMES else block('unrecognized_enum')
        return block('unknown_field')

    def walk(value, depth=0):
        if depth > 32: return block('depth_limit')
        if isinstance(value, list):
            return [walk(v, depth+1) if isinstance(v, (dict, list)) else block('untyped_array_item') for v in value]
        out = {}
        for name, item in value.items():
            normal = re.sub(r'[^a-z0-9]', '', name.lower())
            # Never echo a private suffix hidden by normalization (e.g. user客户甲).
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', name):
                out[pseudonym('FIELD', name)] = block('nonstandard_field_name')
                continue
            # Unknown field names can themselves contain private identifiers.
            known = (normal in CONTAINERS | IDENTIFIERS | IPS | NUMBERS or normal in {
                'name', 'mac', 'macaddress', 'timestamp', 'utctime', 'timecreated', 'systemtime',
                'version', 'productversion', 'image', 'parentimage', 'executable', 'path',
                'targetfilename', 'commandline', 'parentcommandline', 'providername', 'channel',
                'protocol', 'programname'})
            if SECRET.search(normal):
                out[pseudonym('SECRET_FIELD', name)] = '[REMOVED_SECRET]'
            elif not known:
                out[pseudonym('FIELD', name)] = block('unknown_field')
            else:
                out[name] = field(name, item, depth)
        return out

    preview = walk(source)
    # Second pass over sanitized output only. Never returns findings containing original text.
    residual = re.compile(r'(?i)\bBearer\s+\S+|-----BEGIN [^-]*PRIVATE KEY-----|[\w.+-]+@[\w.-]+\.[a-z]{2,}')
    def rescan(value):
        if isinstance(value, dict): return {k: rescan(v) for k, v in value.items()}
        if isinstance(value, list): return [rescan(v) for v in value]
        if isinstance(value, str) and residual.search(value): return block('residual_scan')
        return value
    preview = rescan(preview)
    return {'preview': preview, 'replacements': counts, 'policy_version': POLICY_VERSION,
            'key_id': hashlib.sha256(key).hexdigest()[:16], 'review_flags': sorted(flags),
            'external_send_allowed': False, 'review_required': True,
            'limitations': 'Policy JSON giới hạn; trường lạ và command line tự do bị chặn. Không bảo đảm ẩn danh hoặc giữ đủ đặc trưng. Chưa có đường gửi LLM.'}
