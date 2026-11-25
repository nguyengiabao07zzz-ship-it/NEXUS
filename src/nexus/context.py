"""Additional AI context; free text is opt-in and must be reviewed locally."""
import hashlib
import hmac
import ipaddress
import json
import re

VERSION = 'reviewed-context-v2'
SECRET = re.compile(r'(?i)(?:password|passwd|api[_ -]?key|secret|cookie|credential|token)\s*[=:]\s*\S+|bearer\s+\S+|authorization\s*:|private.key|\bsk-[A-Za-z0-9_-]{10,}|\beyJ[A-Za-z0-9_-]+\.')


def supplement(event, key, include_text=False):
    def pseudonym(kind, value):
        raw=json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))
        code=hmac.new(key,(kind+'\0'+raw).encode(),hashlib.sha256).hexdigest()[:24]
        return '['+kind+'_'+code+']'

    def scrub(value):
        if not isinstance(value,str):
            return '[BLOCKED_TYPE]'
        if SECRET.search(value):
            return '[BLOCKED_POSSIBLE_SECRET]'
        text=value[:4000]
        text=re.sub(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}',lambda m:pseudonym('EMAIL',m[0]),text)
        text=re.sub(r'https?://[^\s<>"\']+',lambda m:pseudonym('URL',m[0]),text)
        # Remove paths as a unit, including spaces in quoted Windows paths.
        text=re.sub(r'(?i)[a-z]:\\[^\r\n"<>]+',lambda m:pseudonym('PATH',m[0]),text)
        text=re.sub(r'/(?:home|Users)/[^\s"\']+',lambda m:pseudonym('PATH',m[0]),text)
        text=re.sub(r'\bS-\d-\d+(?:-\d+){1,15}\b',lambda m:pseudonym('SID',m[0]),text)
        text=re.sub(r'(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b',lambda m:pseudonym('MAC',m[0]),text)
        text=re.sub(r'[A-Za-z0-9+/=_-]{40,}',lambda m:pseudonym('OPAQUE',m[0]),text)
        text=re.sub(r'(?i)\b(?:user(?:name)?|account|host(?:name)?|computer|domain)\s*[=:]\s*[^\s,;]+',lambda m:pseudonym('IDENTITY',m[0]),text)
        text=re.sub(r'(?i)\b(?:for (?:invalid user )?|user )[A-Za-z0-9_.@\\-]+',lambda m:pseudonym('IDENTITY',m[0]),text)
        # Exact known identifiers are scrubbed even when embedded in descriptions.
        identifiers=[]
        def scan(value):
            if isinstance(value,dict):
                for name,item in value.items():
                    if name.lower() in {'name','hostname','computer','username','user','domain','srcuser','dstuser','targetusername','subjectusername','email','targetdomainname','subjectdomainname','usersid','targetusersid','subjectusersid'} and isinstance(item,str) and len(item)>1:
                        if item not in {'sshd','ossec','sudo','pam','json','windows_eventchannel'}:
                            identifiers.append(item)
                    if isinstance(item,(dict,list)):scan(item)
            elif isinstance(value,list):
                for item in value:scan(item)
        scan(event)
        for identity in sorted(set(identifiers),key=len,reverse=True):
            text=re.sub(re.escape(identity),lambda _:pseudonym('IDENTITY',identity),text,flags=re.I)
        def address(match):
            value=match[0]
            try:ipaddress.ip_address(value)
            except ValueError:return value
            return pseudonym('IP',value)
        text=re.sub(r'(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])|(?<![\w])[0-9a-fA-F]*:[0-9a-fA-F:]+(?![\w])',address,text)
        return text

    rule=event.get('rule') if isinstance(event.get('rule'),dict) else {}
    decoder=event.get('decoder') if isinstance(event.get('decoder'),dict) else {}
    output={'policy':VERSION,'text_included':include_text}
    name=decoder.get('name')
    if name in {'ossec','sshd','sudo','pam','json','windows_eventchannel','syscheck_new_entry','syscheck_integrity_changed'}:
        output['decoder']=name
    mitre=rule.get('mitre',{})
    if isinstance(mitre,dict) and isinstance(mitre.get('id'),list):
        output['mitre_ids']=[x for x in mitre['id'][:30] if isinstance(x,str) and re.fullmatch(r'T\d{4}(?:\.\d{3})?',x)]
    # Fixed local patterns preserve behavioral signals without transmitting text.
    raw=' '.join(x for x in (event.get('full_log'),rule.get('description')) if isinstance(x,str))[:16000].lower()
    signals=[]
    for label,pattern in [('authentication_failure',r'failed password|authentication fail|logon failure|invalid user'),
                          ('authentication_success',r'accepted (?:password|publickey)|logon success'),
                          ('integrity_change',r'checksum changed|integrity checksum|file (?:added|deleted|modified)'),
                          ('service_state_change',r'agent (?:disconnected|stopped)|service (?:stopped|started)'),
                          ('privileged_command',r'sudo:|sudo command|privilege')]:
        if re.search(pattern,raw):signals.append(label)
    output['local_pattern_signals']=signals
    flags=[]
    if include_text:
        output['rule_description']=scrub(rule.get('description',''))
        output['event_excerpt']=scrub(event.get('full_log',''))
        flags.append('free_text_requires_human_review_not_anonymous')
    else:
        flags.append('free_text_not_selected')
    return output,flags
