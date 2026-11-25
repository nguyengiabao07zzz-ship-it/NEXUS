import io
import json
from pathlib import Path
import zipfile
from .rules import validate_xml


GUIDE='''NEXUS - Candidate for Ubuntu Wazuh LAB ONLY
This bundle contains no source logs or credentials. Review the XML before running.
Do not use an archive from an untrusted source. Take a VM snapshot first.

1. Extract this ZIP into a separate directory on the Ubuntu Wazuh manager.
2. Inspect (no root needed): python3 lab_helper.py inspect
3. Stage: sudo python3 lab_helper.py stage --confirm-lab
   This adds ONLY nexus_lab_<candidate_id>.xml and runs wazuh-analysisd -t.
   It does not restart the manager. Logtest can load the staged rule.
4. Prepare one-line samples from YOUR AUTHORIZED LAB and test each:
   sudo python3 lab_helper.py logtest --confirm-lab --sample attack.log --decoder DECODER --kind attack
   sudo python3 lab_helper.py logtest --confirm-lab --sample benign.log --decoder DECODER --kind benign --expect-rule EXISTING_RULE --expect-level EXISTING_LEVEL
   sudo python3 lab_helper.py logtest --confirm-lab --sample regression.log --decoder DECODER --kind regression --expect-rule EXISTING_RULE --expect-level EXISTING_LEVEL
   Replace DECODER/RULE/LEVEL with known expected results, not guessed values.
   Zero exit status means matching that exact expected rule/level/decoder only.
5. Activate ONLY after reviewing all tests:
   sudo python3 lab_helper.py activate --confirm-lab
   This requires all three kinds to have passing logtests and restarts wazuh-manager.
6. Roll back the exact staged/active candidate:
   sudo python3 lab_helper.py rollback --confirm-lab

Reports/backups are private at /var/ossec/backup/nexus/<candidate_id>/.
The helper refuses existing target files and duplicate rule IDs. It does not
prove performance/false-positive safety or automate attacks/replays. Use separate
held-out scenarios after tuning. Record source evidence, time window and outcomes
in NEXUS. Importing a check manually is not cryptographic runner verification.
'''


def build_bundle(candidate):
    validation=validate_xml(candidate['xml'])
    manifest={'candidate_id':candidate['id'],'title':candidate['title'],
              'case_id':candidate['case_id'],**validation,'status':'unverified_lab_candidate'}
    memory=io.BytesIO()
    with zipfile.ZipFile(memory,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('nexus_rule.xml',candidate['xml'])
        archive.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
        archive.writestr('README.txt',GUIDE)
        archive.writestr('lab_helper.py',Path(__file__).with_name('lab_helper.py').read_bytes())
    return memory.getvalue()
