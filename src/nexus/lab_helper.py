"""Standalone local Ubuntu lab helper, bundled with a reviewed candidate.

No network, SSH or attack execution. Root operations are explicit CLI actions.
"""
import argparse
from datetime import datetime,timezone
try:
    import grp
except ImportError:
    grp=None  # The exported helper executes privileged operations on Linux only.
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path('/var/ossec')


def sha(data):return hashlib.sha256(data).hexdigest()


def bundle(directory):
    directory=Path(directory)
    manifest=json.loads((directory/'manifest.json').read_text(encoding='utf-8'))
    xml=(directory/'nexus_rule.xml').read_bytes()
    if len(xml)>16000 or sha(xml)!=manifest['sha256'] or not re.fullmatch('[a-f0-9]{32}',manifest['candidate_id']):raise ValueError('Bundle hash/ID invalid')
    if b'<!' in xml or b'<?' in xml:raise ValueError('XML declarations forbidden')
    parsed=ET.fromstring(xml)
    rules=parsed.findall('rule')
    if parsed.tag!='group' or len(rules)!=1:raise ValueError('Expected one rule')
    if int(rules[0].get('id'))!=manifest['rule_id'] or int(rules[0].get('level'))!=manifest['level']:raise ValueError('Manifest does not match XML')
    if not 100000<=manifest['rule_id']<=120000 or not 1<=manifest['level']<=15:raise ValueError('Unsafe rule ID/level')
    return manifest,xml


def target(manifest):return ROOT/'etc/rules'/('nexus_lab_'+manifest['candidate_id']+'.xml')


def state_path(manifest):return ROOT/'backup/nexus'/manifest['candidate_id']/'state.json'


def write_state(manifest,state):
    path=state_path(manifest);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink() or path.parent.is_symlink():raise ValueError('Symlink not allowed')
    temporary=path.with_suffix('.tmp')
    with temporary.open('w',encoding='utf-8') as stream:json.dump(state,stream,indent=2)
    os.chmod(temporary,0o600);temporary.replace(path)


def command(args,input_text=None):
    result=subprocess.run([str(x) for x in args],input=input_text,text=True,
                          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=45)
    return {'argv':[str(x) for x in args],'returncode':result.returncode,'output':result.stdout[-64000:]}


def require_target(manifest):
    file=target(manifest)
    if file.is_symlink() or not file.is_file() or sha(file.read_bytes())!=manifest['sha256']:raise ValueError('Staged file changed; refusing operation')
    state=json.loads(state_path(manifest).read_text(encoding='utf-8'))
    if state['sha256']!=manifest['sha256'] or state['status'] not in ('staged','active'):raise ValueError('State mismatch')
    return state


def stage(manifest,xml):
    file=target(manifest)
    if file.exists() or file.is_symlink():raise ValueError('Target exists; inspect/rollback first')
    if state_path(manifest).exists():raise ValueError('This candidate already has a lab record; create a new candidate version to stage again')
    for directory in (ROOT/'ruleset/rules',ROOT/'etc/rules'):
        for existing in directory.glob('*.xml'):
            data=existing.read_text(encoding='utf-8',errors='replace')
            ids=re.findall(r'<rule\b[^>]*\bid\s*=\s*[\'\"](\d+)[\'\"]',data)
            if any(int(value)==manifest['rule_id'] for value in ids):raise ValueError('Rule ID already exists: '+str(existing))
    state={'sha256':manifest['sha256'],'status':'preparing','created':datetime.now(timezone.utc).isoformat(),
           'was_absent':True,'checks':[],'live_activation':False}
    write_state(manifest,state)
    config=ROOT/'etc/ossec.conf'
    if config.is_file():
        backup=state_path(manifest).parent/'ossec.conf.before'
        backup.write_bytes(config.read_bytes());os.chmod(backup,0o600)
    # Never overwrite manager files or follow a symlink.
    descriptor=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o640)
    with os.fdopen(descriptor,'wb') as stream:stream.write(xml)
    try:
        os.chown(file,0,grp.getgrnam('wazuh').gr_gid)
        report=command([ROOT/'bin/wazuh-analysisd','-t'])
        state['load']=report
        if report['returncode']!=0:raise ValueError('Manager configuration test failed; candidate removed')
        state['status']='staged';write_state(manifest,state)
    except Exception:
        if file.is_file() and sha(file.read_bytes())==manifest['sha256']:file.unlink()
        state['status']='stage_failed';write_state(manifest,state)
        raise
    return state


def logtest(manifest,sample,decoder,expected_rule,expected_level,kind):
    state=require_target(manifest)
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',decoder):raise ValueError('Invalid decoder')
    text=Path(sample).read_text(encoding='utf-8')
    lines=[line for line in text.splitlines() if line.strip()]
    if len(lines)!=1 or len(text)>64000 or '\x00' in text:raise ValueError('Supply exactly one log line, <=64KB')
    if not 1<=expected_rule<=999999 or not 0<=expected_level<=15:raise ValueError('Invalid expected rule/level')
    if kind in ('benign','regression') and expected_rule==manifest['rule_id']:raise ValueError('Benign/regression must expect an existing rule, not this candidate')
    if kind=='attack' and expected_rule!=manifest['rule_id']:raise ValueError('Attack sample must expect this candidate rule')
    report=command([ROOT/'bin/wazuh-logtest','-U',f'{expected_rule}:{expected_level}:{decoder}'],lines[0]+'\n\n')
    check={'kind':kind,'sample_sha256':sha(text.encode()),'candidate_sha256':manifest['sha256'],
           'expected_rule':expected_rule,'expected_level':expected_level,'decoder':decoder,
           'result':'pass' if report['returncode']==0 else 'failed_or_error','report':report}
    state['checks'].append(check);write_state(manifest,state)
    return check


def rollback(manifest):
    state=require_target(manifest)
    target(manifest).unlink()  # Only this exact previously-absent file, hash checked above.
    state['status']='rolled_back';write_state(manifest,state)
    if state['live_activation']:
        state['rollback_restart']=command(['systemctl','restart','wazuh-manager'])
        write_state(manifest,state)
        if state['rollback_restart']['returncode']!=0:raise ValueError('File removed but manager restart failed; manual intervention required')
    return state


def activate(manifest):
    state=require_target(manifest)
    latest={x['kind']:x for x in state['checks']}
    passed={kind for kind,x in latest.items() if x['result']=='pass' and x['candidate_sha256']==manifest['sha256']}
    if not {'attack','benign','regression'}<=passed:raise ValueError('Need passing attack, benign and regression logtests for this exact candidate first')
    loaded=command([ROOT/'bin/wazuh-analysisd','-t'])
    if loaded['returncode']!=0:raise ValueError('Configuration check failed; not restarting')
    state['live_activation']=True;write_state(manifest,state)
    try:
        report=command(['systemctl','restart','wazuh-manager'])
        active=command(['systemctl','is-active','wazuh-manager'])
        if report['returncode']!=0 or active['returncode']!=0:raise ValueError('Manager not active')
    except (ValueError,OSError,subprocess.SubprocessError):
        rollback(manifest)
        raise ValueError('Activation failed; candidate removed and restart attempted; inspect manager')
    state.update(status='active',activation=report);write_state(manifest,state)
    return state


def main():
    parser=argparse.ArgumentParser(description='NEXUS: explicit Ubuntu lab operations only')
    parser.add_argument('action',choices=['inspect','stage','logtest','activate','rollback'])
    parser.add_argument('--bundle',default=str(Path(__file__).resolve().parent))
    parser.add_argument('--confirm-lab',action='store_true')
    parser.add_argument('--sample');parser.add_argument('--decoder')
    parser.add_argument('--expect-rule',type=int);parser.add_argument('--expect-level',type=int)
    parser.add_argument('--kind',choices=['attack','benign','regression'],default='attack')
    args=parser.parse_args()
    lock=None
    try:
        manifest,xml=bundle(args.bundle)
        if args.action=='inspect':
            print(json.dumps(manifest,indent=2));return
        if sys.platform!='linux' or os.geteuid()!=0 or not args.confirm_lab:raise ValueError('Run as root on your Ubuntu lab with --confirm-lab')
        import fcntl
        lock_root=ROOT/'backup/nexus'
        lock_root.mkdir(parents=True,exist_ok=True,mode=0o700)
        lock_path=lock_root/'.operations.lock'
        if lock_root.is_symlink() or lock_path.is_symlink():raise ValueError('Symlink not allowed')
        lock=lock_path.open('a')
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='stage':result=stage(manifest,xml)
        elif args.action=='logtest':
            if not args.sample or not args.decoder:raise ValueError('logtest requires --sample and --decoder')
            result=logtest(manifest,args.sample,args.decoder,args.expect_rule or manifest['rule_id'],manifest['level'] if args.expect_level is None else args.expect_level,args.kind)
        elif args.action=='activate':result=activate(manifest)
        else:result=rollback(manifest)
        print(json.dumps({'status':result.get('status',result.get('result')),'private_report':str(state_path(manifest))}))
        if result.get('result')=='failed_or_error':raise ValueError('Logtest did not match expected rule/level/decoder; inspect private report')
    except (ValueError,OSError,KeyError,ET.ParseError,subprocess.SubprocessError) as exc:
        parser.exit(1,'Lab operation failed: '+str(exc)+'\n')
    finally:
        if lock is not None:lock.close()


if __name__=='__main__':main()
