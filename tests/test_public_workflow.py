"""Parked admission execution and dependency contract, not hosted ordering proof."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
WF=ROOT/'.github/workflows/ai09-public-safe-pilot.yml'
PUBLIC=ROOT/'.github/workflows/ai09-public-boundary-ci.yml'


def job(text,name):
    found=re.search(r'^  '+re.escape(name)+r':\n(.*?)(?=^  [a-zA-Z][a-zA-Z0-9_-]*:|\Z)',text,re.M|re.S)
    if not found:raise AssertionError('required parked job missing: '+name)
    return found.group(1)


def condition(block,values):
    found=re.search(r'^    if: (.*)$',block,re.M)
    if not found:raise AssertionError('job condition missing')
    expression=found.group(1).strip()
    if expression.startswith('${{') and expression.endswith('}}'):expression=expression[3:-2].strip()
    results=[]
    for term in expression.split(' && '):
        match=re.fullmatch(r"(needs\.admission\.result|github\.ref|github\.event_name) == '([^']+)'",term.strip())
        if not match:raise AssertionError('unsupported or broader parked condition')
        results.append(values[match[1]]==match[2])
    return all(results)


def steps(block):
    return re.split(r'^      - name: ',block,flags=re.M)[1:]


class PublicWorkflowBoundaryTest(unittest.TestCase):
    def test_unbound_admission_fails_before_any_action_with_canary_values(self):
        admission=job(WF.read_text(),'admission')
        for forbidden in ('environment:','uses:','secrets.','continue-on-error'):
            self.assertNotIn(forbidden,admission)
        self.assertIn('    permissions: {}',admission)
        first=steps(admission);self.assertEqual(len(first),1)
        match=re.search(r'        run: \|\n((?:          .*\n?)+)',first[0]);self.assertIsNotNone(match)
        script='\n'.join(line[10:] for line in match.group(1).splitlines())
        self.assertEqual(script.splitlines(),["echo 'PRIVATE_ACTIVATION_NOT_AUTHORIZED; DESIGN_APPROVAL=HOLD'",'exit 1'])
        bash=shutil.which('bash')
        if os.name=='nt':bash=r'C:\Program Files\Git\bin\bash.exe'
        self.assertTrue(bash and pathlib.Path(bash).is_file())
        with tempfile.TemporaryDirectory() as temp:
            env={'PATH':os.defpath,'RUNNER_TEMP':temp,'GITHUB_REF':'refs/heads/main',
                 'AI09_ENABLE_PILOT':'true','AI09_BUNDLE_KEY_B64':'PUBLIC-KEY-CANARY',
                 'GITHUB_OUTPUT':str(pathlib.Path(temp)/'command'),'GITHUB_EVENT_NAME':'workflow_dispatch'}
            result=subprocess.run([bash,'--noprofile','--norc'],input=script,text=True,
                cwd=temp,env=env,capture_output=True,timeout=3)
            self.assertEqual(result.returncode,1)
            self.assertEqual(result.stdout,'PRIVATE_ACTIVATION_NOT_AUTHORIZED; DESIGN_APPROVAL=HOLD\n')
            self.assertEqual(result.stderr,'');self.assertEqual(list(pathlib.Path(temp).iterdir()),[])

    def test_environment_job_requires_successful_admission_manual_main_only(self):
        text=WF.read_text();admission=job(text,'admission');pilot=job(text,'isolated-pilot')
        self.assertRegex(pilot,r'(?m)^    needs: \[admission\]$')
        self.assertRegex(pilot,r'(?m)^    environment: ai09-private-pilot$')
        for state in ('success','failure','cancelled','skipped'):
            for ref in ('refs/heads/main','refs/heads/other','refs/pull/2/merge'):
                for event in ('workflow_dispatch','push','pull_request'):
                    values={'needs.admission.result':state,'github.ref':ref,'github.event_name':event}
                    self.assertEqual(condition(pilot,values),state=='success' and ref=='refs/heads/main' and event=='workflow_dispatch')
                    self.assertEqual(condition(admission,values),ref=='refs/heads/main' and event=='workflow_dispatch')
        self.assertNotIn('always()',pilot)
        self.assertEqual(text.count('environment: ai09-private-pilot'),1)

    def test_three_optional_public_identity_inputs_cannot_enable_execution(self):
        header=WF.read_text().split('\njobs:',1)[0]
        self.assertEqual(re.findall(r'^      ([a-z0-9_]+):$',header,re.M),
            ['approved_main_sha','input_ciphertext_sha256','input_ciphertext_bytes'])
        for line in ('        type: string','        required: false',"        default: ''"):
            self.assertEqual(header.count(line),3)
        self.assertNotRegex(header,r'(?m)^\s+(push|pull_request|workflow_call):')
        self.assertIn('workflow_dispatch:',header)

    def test_key_and_identity_inputs_are_only_at_the_fixed_coordinator_step(self):
        text=WF.read_text();pilot=job(text,'isolated-pilot')
        keyed=[part for part in steps(pilot) if 'secrets.AI09_BUNDLE_KEY_B64' in part]
        self.assertEqual(len(keyed),1);coordinator=keyed[0]
        self.assertIn('        id: coordinator',coordinator)
        for key,value in (('AI09_APPROVED_MAIN_SHA','approved_main_sha'),
            ('AI09_INPUT_CIPHERTEXT_SHA256','input_ciphertext_sha256'),('AI09_INPUT_CIPHERTEXT_BYTES','input_ciphertext_bytes')):
            self.assertIn('          '+key+': ${{ inputs.'+value+' }}',coordinator)
        self.assertIn('          python -I -B tools/private_pilot.py',coordinator)
        self.assertNotIn('${{',coordinator.split('        run: |',1)[1])
        self.assertNotIn('AI09_BUNDLE_KEY_B64',pilot.split('    steps:',1)[0])
        self.assertEqual(text.count('secrets.'),1)

    def test_pinned_public_setup_precedes_secret_and_legacy_private_python_is_gone(self):
        text=WF.read_text();parts=steps(job(text,'isolated-pilot'))
        index=next(i for i,s in enumerate(parts) if 'secrets.' in s)
        before='\n'.join(parts[:index]);after='\n'.join(parts[index+1:])
        for required in ('actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
            'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065','persist-credentials: false',
            '--require-hashes -r requirements-public.txt',"['docker', 'pull', IMAGE]"):
            self.assertIn(required,before)
        self.assertNotIn('pip install',after)
        for legacy in ('open-bundle','seal-evidence','reviewer.py','checkpoint_runner.py',
                       'local_inference_gate.py','sudo tar','ollama serve','ollama pull'):
            self.assertNotIn(legacy,text)

    def test_artifact_proposal_is_disabled_success_only_and_one_exact_ciphertext(self):
        uploads=[s for s in steps(job(WF.read_text(),'isolated-pilot')) if 'upload-artifact@' in s]
        self.assertEqual(len(uploads),1);upload=uploads[0]
        match=re.search(r'        if: \$\{\{ (.*) \}\}',upload);self.assertIsNotNone(match)
        terms=match.group(1).split(' && ')
        self.assertEqual(terms,['false','success()',"steps.coordinator.outcome == 'success'"])
        for success in (False,True):
            for outcome in ('success','failure','cancelled','skipped'):
                values={'false':False,'success()':success,"steps.coordinator.outcome == 'success'":outcome=='success'}
                self.assertFalse(all(values[term] for term in terms))
        for required in ('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
            'path: ${{ runner.temp }}/ai09-private-pilot-${{ github.run_id }}-${{ github.run_attempt }}/ai09-observed-evidence.aesgcm',
            'retention-days: 1','if-no-files-found: error'):
            self.assertIn(required,upload)
        self.assertNotIn('*',upload);self.assertNotIn('secrets.',upload)

    def test_readonly_permissions_and_no_cancelling_concurrency_are_preserved(self):
        text=WF.read_text();self.assertEqual(text.count('contents: read'),2)
        self.assertNotRegex(text,r'(?m)^\s+\S+: write\s*$')
        self.assertIn('cancel-in-progress: false',text)
        self.assertIn('timeout-minutes: 35',job(text,'isolated-pilot'))

    def test_public_ci_new_paths_do_not_add_private_steps_or_model_calls(self):
        text=PUBLIC.read_text();jobs=text.split('\njobs:',1)[1]
        self.assertNotIn('secrets.',text)
        self.assertNotIn('tools/private_pilot.py',jobs);self.assertNotIn('owner_bundle.py',jobs)
        self.assertEqual(jobs.count('python3 -I tools/public_model_smoke.py'),1)
        for name in ('private_pilot.py','tools/private_pilot.py','tests/test_private_pilot.py',
            'tests/fixtures/private_pilot_child.py','tools/owner_bundle.py','tests/test_owner_bundle.py'):
            self.assertIn('      - '+name+'\n',text)


if __name__=='__main__':unittest.main()
