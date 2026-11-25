import hashlib
import hmac
from contextlib import contextmanager
import json
import re
import sqlite3
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


class Invalid(ValueError):
    pass


def load_json_bounded(text, **kwargs):
    if isinstance(text, bytes):
        text = text.decode('utf-8')
    depth, quoted, escaped = 0, False, False
    for character in text:
        if quoted:
            if escaped: escaped = False
            elif character == '\\': escaped = True
            elif character == '"': quoted = False
        elif character == '"': quoted = True
        elif character in '[{':
            depth += 1
            if depth > 64: raise Invalid('JSON vượt giới hạn độ sâu')
        elif character in ']}': depth -= 1
    return json.loads(text, **kwargs)


FIELDS = {
    'case': {'title', 'technique', 'source', 'criteria', 'environment', 'split'},
    'evidence': {'label', 'content', 'origin', 'role'},
    'run': {'case_id', 'phase', 'execution', 'notes', 'execution_evidence',
            'observation_evidence', 'candidate_id', 'log_present', 'alert_matches'},
    'candidate': {'title', 'xml', 'rationale', 'case_id', 'playbook', 'parent_id'},
    'check': {'candidate_id', 'step', 'result', 'evidence_id', 'notes'},
    'review': {'candidate_id', 'reviewer', 'decision', 'notes'},
    'supersede': {'target_id', 'reason', 'by'},
}
REQUIRED = {
    'case': ('title', 'technique', 'source', 'criteria', 'environment', 'split'),
    'evidence': ('label', 'content', 'origin'),
    'run': ('case_id', 'phase', 'execution', 'notes'),
    'candidate': ('title', 'xml', 'rationale', 'case_id', 'playbook'),
    'check': ('candidate_id', 'step', 'result', 'evidence_id', 'notes'),
    'review': ('candidate_id', 'reviewer', 'decision', 'notes'),
    'supersede': ('target_id', 'reason', 'by'),
}
OUTCOMES = ('detected', 'log_without_alert', 'no_log', 'inconclusive', 'execution_failed', 'blocked')
OBSERVATION_ROLES = ('source_log', 'manager_log', 'alert')


def validate_input(kind, data):
    if not isinstance(kind, str) or kind not in FIELDS or not isinstance(data, dict):
        raise Invalid('Loại bản ghi hoặc data không hợp lệ')
    unknown = set(data) - FIELDS[kind]
    if unknown:
        raise Invalid('Có trường không được phép')
    for field, value in data.items():
        if field in ('log_present', 'alert_matches'):
            if value is not None and type(value) is not bool:
                raise Invalid(f'{field} phải là true, false hoặc null')
        elif not isinstance(value, str):
            raise Invalid(f'{field} phải là chuỗi')
    required(data, *REQUIRED[kind])


def required(data, *fields):
    for name in fields:
        if not isinstance(data.get(name), str) or not data[name].strip():
            raise Invalid(f"Thiếu {name}")


def classify(data):
    for name in ('log_present', 'alert_matches'):
        if data.get(name) is not None and type(data[name]) is not bool:
            raise Invalid(f'{name} phải là true, false hoặc null')
    status = data.get('execution')
    if status not in ('success', 'failed', 'blocked', 'unknown'):
        raise Invalid('execution không hợp lệ')
    if status != 'success':
        return {'failed': 'execution_failed', 'blocked': 'blocked', 'unknown': 'inconclusive'}[status]
    if not data.get('execution_evidence') or not data.get('observation_evidence'):
        return 'inconclusive'
    if data.get('alert_matches') is True:
        if data.get('log_present') is False:
            raise Invalid('Cảnh báo phù hợp và không có log là hai nhận định mâu thuẫn')
        return 'detected'
    if data.get('alert_matches') is None or data.get('log_present') is None:
        return 'inconclusive'
    return 'log_without_alert' if data['log_present'] else 'no_log'


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, created TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, record_id TEXT NOT NULL,
                    action TEXT NOT NULL, sha256 TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS immutable_records BEFORE UPDATE ON records
                    BEGIN SELECT RAISE(ABORT, 'records are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS no_delete_records BEFORE DELETE ON records
                    BEGIN SELECT RAISE(ABORT, 'records are immutable'); END;
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def scan(self, kind=None):
        with self.connect() as db:
            rows = db.execute('SELECT id,kind,created,body FROM records ORDER BY created,id').fetchall()
        items, corrupt = [], 0
        for identifier, k, created, body in rows:
            if kind is not None and kind != k:
                continue
            try:
                data = load_json_bounded(body)
                if k not in FIELDS or not isinstance(data, dict):
                    raise Invalid('Stored record shape')
                # Legacy evidence without role stays readable, but cannot qualify a lab run.
                allowed_derived = {'outcome', 'sha256', 'validation', 'candidate_sha256', 'candidate_source_case_id', 'provenance'}
                validate_input(k, {name: value for name, value in data.items() if name not in allowed_derived})
                if k == 'run' and (data.get('phase') not in ('baseline', 'tuned') or
                                   data.get('outcome') != classify(data)):
                    raise Invalid('Stored run shape')
                items.append(dict(data, id=identifier, kind=k, created=created))
            except (ValueError, TypeError, RecursionError):
                corrupt += 1
        return items, corrupt

    def list(self, kind=None):
        return self.scan(kind)[0]

    def get(self, identifier, kind=None):
        for item in self.list(kind):
            if item['id'] == identifier:
                return item
        raise Invalid('Không tìm thấy bản ghi phù hợp')

    def add(self, kind, data):
        validate_input(kind, data)
        data = dict(data)
        if kind == 'case':
            required(data, 'title', 'technique', 'source', 'criteria', 'environment', 'split')
            if not re.fullmatch(r'T\d{4}(?:\.\d{3})?', data['technique']):
                raise Invalid('Mã ATT&CK không hợp lệ')
            if data['split'] not in ('development', 'held_out'):
                raise Invalid('split không hợp lệ')
        elif kind == 'evidence':
            required(data, 'label', 'content', 'origin', 'role')
            if data['origin'] not in ('lab', 'fixture'):
                raise Invalid('origin phải là lab hoặc fixture')
            if data['role'] not in ('execution', *OBSERVATION_ROLES):
                raise Invalid('role bằng chứng không hợp lệ')
            data['sha256'] = hashlib.sha256(data['content'].encode()).hexdigest()
        elif kind == 'run':
            required(data, 'case_id', 'phase', 'execution', 'notes')
            evaluation_case = self.get(data['case_id'], 'case')
            if data['phase'] not in ('baseline', 'tuned'):
                raise Invalid('phase không hợp lệ')
            if data.get('execution_evidence') and data.get('execution_evidence') == data.get('observation_evidence'):
                raise Invalid('Hai vai bằng chứng không được trùng ID')
            for field, roles in (('execution_evidence', ('execution',)),
                                 ('observation_evidence', OBSERVATION_ROLES)):
                if data.get(field):
                    evidence = self.get(data[field], 'evidence')
                    if evidence.get('role') not in roles:
                        raise Invalid('Bằng chứng thiếu role hoặc sai vai trò')
            if data['phase'] == 'tuned':
                required(data, 'candidate_id')
                candidate = self.get(data['candidate_id'], 'candidate')
                source_case = self.get(candidate['case_id'], 'case')
                if source_case['split'] != 'development':
                    raise Invalid('Candidate phải được phát triển từ ca development')
                if candidate['case_id'] != data['case_id'] and evaluation_case['split'] != 'held_out':
                    raise Invalid('Ca development phải dùng candidate cùng ca; candidate khác ca chỉ dùng để đánh giá held_out')
                # Pin the immutable version evaluated; evaluating held-out does
                # not create or modify a candidate from that case.
                data['candidate_sha256'] = candidate['sha256']
                data['candidate_source_case_id'] = source_case['id']
            elif data.get('candidate_id'):
                raise Invalid('Baseline không được có candidate')
            data['outcome'] = classify(data)
        elif kind == 'candidate':
            required(data, 'title', 'xml', 'rationale', 'case_id', 'playbook')
            case = self.get(data['case_id'], 'case')
            if case['split'] != 'development':
                raise Invalid('Chỉ tạo candidate từ ca development; giữ held_out cho đánh giá')
            if '<!DOCTYPE' in data['xml'].upper() or '<!ENTITY' in data['xml'].upper():
                raise Invalid('Không nhận DTD/entity')
            try:
                root = ET.fromstring(data['xml'])
            except ET.ParseError as e:
                raise Invalid('XML chưa well-formed: ' + str(e)) from e
            if root.tag != 'group' or not root.findall('rule'):
                raise Invalid('Cần phần tử group chứa rule')
            data['sha256'] = hashlib.sha256(data['xml'].encode()).hexdigest()
            data['validation'] = 'xml_well_formed_only'
            if data.get('parent_id'):
                if self.get(data['parent_id'], 'candidate')['case_id'] != data['case_id']:
                    raise Invalid('Parent candidate phải thuộc cùng ca thử')
        elif kind == 'check':
            required(data, 'candidate_id', 'step', 'result', 'evidence_id', 'notes')
            candidate = self.get(data['candidate_id'], 'candidate')
            self.get(data['evidence_id'], 'evidence')
            if data['step'] not in ('load', 'logtest', 'replay', 'benign', 'regression'):
                raise Invalid('Bước kiểm tra không hợp lệ')
            if data['result'] not in ('pass', 'fail', 'na'):
                raise Invalid('Kết quả không hợp lệ')
            data['candidate_sha256'] = candidate['sha256']
            data['provenance'] = 'manual_record_not_runner_verified'
        elif kind == 'review':
            required(data, 'candidate_id', 'reviewer', 'decision', 'notes')
            self.get(data['candidate_id'], 'candidate')
            if data['decision'] not in ('reject', 'request_changes'):
                raise Invalid('Chưa hỗ trợ duyệt triển khai khi runner chưa kiểm chứng')
        elif kind == 'supersede':
            self.get(data['target_id'], 'run')
        else:
            raise Invalid('Loại bản ghi không hợp lệ')
        identifier = uuid.uuid4().hex
        stamp = datetime.now(timezone.utc).isoformat(timespec='microseconds')
        body = json.dumps(data, ensure_ascii=False, sort_keys=True)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if kind == 'supersede':
                rows = db.execute("SELECT body FROM records WHERE kind='supersede'").fetchall()
                for (previous,) in rows:
                    try:
                        if json.loads(previous).get('target_id') == data['target_id']:
                            raise Invalid('Run này đã được loại khỏi báo cáo')
                    except (json.JSONDecodeError, AttributeError):
                        continue
            db.execute('INSERT INTO records VALUES (?,?,?,?)', (identifier, kind, stamp, body))
            db.execute('INSERT INTO audit(at,record_id,action,sha256) VALUES (?,?,?,?)',
                       (stamp, identifier, 'create:' + kind, hashlib.sha256(body.encode()).hexdigest()))
        return self.get(identifier)

    def report(self):
        records, corrupt = self.scan()
        by_id = {r['id']: r for r in records}
        excluded = {r['target_id'] for r in records if r['kind'] == 'supersede'
                    and by_id.get(r['target_id'], {}).get('kind') == 'run'}
        runs = [r for r in records if r['kind'] == 'run' and r['id'] not in excluded]

        def provenance(run):
            # Failed/blocked runs still have a source even without telemetry to observe.
            execution = by_id.get(run.get('execution_evidence'), {})
            if execution.get('kind') != 'evidence' or execution.get('role') != 'execution':
                return 'unknown'
            evidences = [execution]
            observation_id = run.get('observation_evidence')
            if observation_id:
                observation = by_id.get(observation_id, {})
                if (observation_id == execution['id'] or observation.get('kind') != 'evidence' or
                        observation.get('role') not in OBSERVATION_ROLES):
                    return 'unknown'
                evidences.append(observation)
            elif run['execution'] == 'success':
                return 'unknown'
            origins = {e.get('origin') for e in evidences}
            if origins == {'lab'}: return 'lab'
            if origins == {'fixture'}: return 'fixture'
            return 'mixed' if origins == {'fixture', 'lab'} else 'unknown'

        def counts(selected):
            return {'total_runs': len(selected), 'phases': {
                phase: {label: sum(r['phase'] == phase and r['outcome'] == label for r in selected)
                        for label in OUTCOMES} for phase in ('baseline', 'tuned')}}

        return {'unit': 'run', 'protocol_status': 'draft_no_technique_coverage',
                'groups': {origin: counts([r for r in runs if provenance(r) == origin])
                           for origin in ('lab', 'fixture', 'mixed', 'unknown')},
                'active_runs': len(runs), 'superseded_runs': len(excluded),
                'corrupt_records': corrupt, 'technique_coverage': None,
                'provenance_basis': 'manual_metadata_not_evidence_content_verified'}


from .privacy import redact
