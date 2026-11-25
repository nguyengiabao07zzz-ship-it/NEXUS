"""Local, bounded inspection of manually supplied Wazuh-shaped JSON/JSONL.

No transport, persistence, threat verdict, suppression or research run creation.
Declared source/origin and event shape are not independently verified.
"""
import hashlib
import json

from .core import Invalid, load_json_bounded

MAX_TEXT_BYTES = 1_000_000
MAX_EVENTS = 500


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise Invalid('JSON có tên trường trùng')
        result[name] = value
    return result


def _constant(_):
    raise Invalid('JSON có số không hợp lệ')


def _parse(text):
    return load_json_bounded(text, object_pairs_hook=_pairs, parse_constant=_constant)


def _label(value):
    if value is None:
        return None
    if type(value) not in (str, int) or len(str(value)) > 128:
        raise Invalid('Trường phân nhóm không đúng kiểu hoặc vượt 128 ký tự')
    return str(value)


def inspect_events(text, source, origin):
    if source not in ('alerts', 'archives') or origin not in ('fixture', 'lab'):
        raise Invalid('Cần chọn nguồn alerts/archives và xuất xứ fixture/lab')
    if not isinstance(text, str) or not text.strip():
        raise Invalid('Cần nội dung JSON hoặc JSONL')
    if len(text.encode('utf-8')) > MAX_TEXT_BYTES:
        raise Invalid('Nội dung log vượt 1 MB')
    cleaned = text.lstrip('\ufeff').strip()
    try:
        parsed = _parse(cleaned)
        events = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        events = []
        for line_number, line in enumerate(cleaned.splitlines(), 1):
            if not line.strip():
                continue
            if len(events) >= MAX_EVENTS:
                raise Invalid('Chỉ nhận tối đa 500 event mỗi lần')
            try:
                events.append(_parse(line))
            except (ValueError, RecursionError):
                raise Invalid(f'JSONL không hợp lệ tại dòng {line_number}') from None
    except (ValueError, RecursionError):
        raise Invalid('JSON không hợp lệ hoặc vượt giới hạn') from None
    if not events or len(events) > MAX_EVENTS:
        raise Invalid('Cần từ 1 đến 500 event')

    groups, fingerprints, rule_count = {}, set(), 0
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict):
            raise Invalid(f'Event {index} phải là JSON object')
        agent = event.get('agent')
        if (not isinstance(agent, dict) or not isinstance(event.get('timestamp'), str)
                or not event['timestamp'].strip() or not agent.get('id')
                or not (isinstance(event.get('full_log'), str) or isinstance(event.get('data'), dict))):
            raise Invalid(f'Event {index} thiếu timestamp, agent.id hoặc full_log/data')
        rule, decoder = event.get('rule', {}), event.get('decoder', {})
        if not isinstance(rule, dict) or not isinstance(decoder, dict):
            raise Invalid(f'Event {index} có rule/decoder sai kiểu')
        rule_id = _label(rule.get('id'))
        if source == 'alerts' and not rule_id:
            raise Invalid(f'Event {index} từ alerts cần rule.id')
        rule_count += bool(rule_id)
        # Separate agents, rules and decoders; retain every original event index.
        key = (_label(agent['id']), rule_id, _label(decoder.get('name')))
        if key not in groups:
            groups[key] = dict(agent_id=key[0], rule_id=key[1], decoder=key[2], event_indexes=[])
        groups[key]['event_indexes'].append(index)
        canonical = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        fingerprints.add(hashlib.sha256(canonical.encode('utf-8')).hexdigest())

    return {
        'provenance': 'manual_import_preview_not_collector_verified',
        'declared_source': source, 'declared_origin': origin,
        'input_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
        'total_events': len(events), 'events_with_rule_id': rule_count,
        'events_without_rule_id': len(events) - rule_count,
        'repeated_content_count': len(events) - len(fingerprints),
        'groups': [dict(group, count=len(group['event_indexes'])) for group in groups.values()],
        'persisted': False, 'external_send_allowed': False,
        'limitations': [
            'Nguồn do người nhập khai báo, chưa xác minh nội dung hoặc kết nối Wazuh.',
            'Gom cùng agent/rule/decoder chỉ để xem; chưa tương quan thời gian hoặc kết luận nhiễu/nguy hiểm.',
            'Không bỏ event; nội dung giống nhau chưa chứng minh ingest trùng.',
            'Thiếu rule.id không chứng minh Wazuh bỏ sót hoặc event là tấn công.',
            'Preview nội bộ chưa làm sạch để gửi LLM; không tạo run hoặc số liệu nghiên cứu.',
        ],
    }
