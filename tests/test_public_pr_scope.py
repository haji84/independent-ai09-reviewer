"""Synthetic GitHub responses: do not call the network or any external model."""
import copy
import json
import unittest
from hashlib import sha256
from pathlib import Path

from public_pr_scope import AdmissionBlocked, admit_public_pr, PUBLIC_TARGETS

REPO = 'haji84/AI-VIDEO-STUDIO'
BASE = 'e1bf222dfe0043e307e3fc3c122e2fe52423dac8'
HEAD = '465a1111df0fbf91f0073b4c726a8a0c0182ff44'
BRANCH = 'feat/audio-preview-parity-20261102'
RUN = 41386923713


def fixture():
    return {
        f'/repos/{REPO}': {
            'full_name': REPO, 'private': False, 'visibility': 'public',
            'fork': False, 'default_branch': 'main'},
        f'/repos/{REPO}/pulls/26': {
            'number': 26, 'state': 'open', 'changed_files': 1,
            'head': {'sha': HEAD, 'ref': BRANCH, 'repo': {'full_name': REPO}},
            'base': {'sha': BASE, 'ref': 'main', 'repo': {'full_name': REPO}}},
        f'/repos/{REPO}/actions/runs/{RUN}': {
            'id': RUN, 'status': 'completed', 'conclusion': 'success',
            'head_sha': HEAD, 'head_branch': BRANCH,
            'event': 'workflow_dispatch', 'repository': {'full_name': REPO},
            'run_attempt': 1, 'path': '.github/workflows/manual-smoke.yml'},
        f'/repos/{REPO}/actions/runs/{RUN}/jobs': {
            'total_count': 2, 'jobs': [
                {'name': 'offline-prototype-smoke', 'status': 'completed',
                 'conclusion': 'success', 'head_sha': HEAD},
                {'name': 'synthetic-browser-acceptance', 'status': 'completed',
                 'conclusion': 'success', 'head_sha': HEAD},
            ]},
        f'/repos/{REPO}/compare/{BASE}...{HEAD}': {
            'status': 'ahead', 'base_commit': {'sha': BASE},
            'commits': [{'sha': HEAD}], 'total_commits': 1,
            'files': [{'filename': 'apps/local-editor/module.mjs',
                       'patch': '@@ -0,0 +1 @@\n+export const answer=42;',
                       'status': 'added'}]},
    }


def call(data, *, repo=REPO, expected=HEAD, run=RUN, targets=PUBLIC_TARGETS):
    def get(path):
        if path not in data:
            raise AssertionError('Unexpected API path: '+path)
        return copy.deepcopy(data[path])
    return admit_public_pr(repo, 26, expected, run, get=get, targets=targets)


class PublicAdmissionTest(unittest.TestCase):
    def test_exact_public_pr_and_full_ci_and_patch_evidence_admitted_but_not_reviewed(self):
        evidence = call(fixture())
        receipt = evidence.receipt()
        self.assertEqual(receipt['admission'], 'PUBLIC_SOURCE_VERIFIED')
        self.assertEqual(receipt['independent_model_review'], 'NOT_RUN')
        self.assertFalse(receipt['github_approval_satisfied'])
        self.assertFalse(receipt['merge_authorized'])
        self.assertEqual(receipt['head_sha'], HEAD)
        self.assertEqual(receipt['paths'], ['apps/local-editor/module.mjs'])
        diff = 'diff --git a/apps/local-editor/module.mjs b/apps/local-editor/module.mjs\n@@ -0,0 +1 @@\n+export const answer=42;'
        self.assertEqual(receipt['patch_sha256'], sha256(diff.encode()).hexdigest())
        self.assertNotIn('answer=42', json.dumps(receipt))

    def check_blocked(self, data, key):
        with self.assertRaises(AdmissionBlocked) as c:
            call(data)
        self.assertEqual(str(c.exception), key)

    def test_draft_allowed_for_nonbinding_advisory(self):
        d = fixture()
        d[f'/repos/{REPO}/pulls/26']['draft'] = True
        self.assertEqual(call(d).head_sha, HEAD)

    def test_stale_ci_sha_is_not_upgraded_by_old_success(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}']['head_sha'] = '7c972adc77979d58dde84f0b7dbdc334a63f2abc'
        self.check_blocked(d, 'CI_NOT_VERIFIED_ON_EXACT_HEAD')

    def test_head_mutated_before_review_is_rejected(self):
        d = fixture()
        d[f'/repos/{REPO}/pulls/26']['head']['sha'] = '7c972adc77979d58dde84f0b7dbdc334a63f2abc'
        self.check_blocked(d, 'STALE_OR_FOREIGN_PR')

    def test_wrong_ci_path_blocked(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}']['path'] = '.github/workflows/other.yml'
        self.check_blocked(d, 'CI_NOT_VERIFIED_ON_EXACT_HEAD')

    def test_wrong_run_branch_blocked(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}']['head_branch'] = 'main'
        self.check_blocked(d, 'CI_NOT_VERIFIED_ON_EXACT_HEAD')

    def test_failure_not_admissible(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}']['conclusion'] = 'failure'
        self.check_blocked(d, 'CI_NOT_VERIFIED_ON_EXACT_HEAD')

    def test_unapproved_repository_cannot_trigger_public_review(self):
        with self.assertRaises(AdmissionBlocked) as e:
            call(fixture(), targets={})
        self.assertEqual(str(e.exception), 'REPOSITORY_NOT_APPROVED')

    def test_private_target_is_not_read(self):
        d = fixture()
        d[f'/repos/{REPO}']['private'] = True
        self.check_blocked(d, 'TARGET_NOT_VERIFIED_PUBLIC')

    def test_forked_repository_refused(self):
        d = fixture()
        d[f'/repos/{REPO}']['fork'] = True
        self.check_blocked(d, 'TARGET_NOT_VERIFIED_PUBLIC')

    def test_foreign_pr_head_refused(self):
        d = fixture()
        d[f'/repos/{REPO}/pulls/26']['head']['repo']['full_name'] = 'attacker/fork'
        self.check_blocked(d, 'STALE_OR_FOREIGN_PR')

    def test_incomplete_file_list_is_not_counted_as_complete_review(self):
        d = fixture()
        d[f'/repos/{REPO}/pulls/26']['changed_files'] = 2
        self.check_blocked(d, 'INCOMPLETE_COMPARE_EVIDENCE')

    def test_absent_binary_patch_refused(self):
        d = fixture()
        d[f'/repos/{REPO}/compare/{BASE}...{HEAD}']['files'][0]['patch'] = None
        self.check_blocked(d, 'UNREVIEWABLE_PATCH_FILE')

    def test_path_traversal_refused(self):
        d = fixture()
        d[f'/repos/{REPO}/compare/{BASE}...{HEAD}']['files'][0]['filename'] = '../private/secret'
        self.check_blocked(d, 'UNREVIEWABLE_PATCH_FILE')

    def test_oversized_diff_refused_without_truncation(self):
        d = fixture()
        d[f'/repos/{REPO}/compare/{BASE}...{HEAD}']['files'][0]['patch'] = '@@ -0,0 +1 @@\n+' + 'X'*130_000
        self.check_blocked(d, 'REVIEW_PATCH_BUDGET_EXCEEDED')

    def test_truncated_commit_list_refused(self):
        d = fixture()
        d[f'/repos/{REPO}/compare/{BASE}...{HEAD}']['total_commits'] = 250
        self.check_blocked(d, 'INCOMPLETE_COMPARE_EVIDENCE')

    def test_required_chrome_job_cannot_be_skipped(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}/jobs']['jobs'][1]['conclusion'] = 'skipped'
        self.check_blocked(d, 'REQUIRED_CI_JOBS_NOT_VERIFIED')

    def test_incomplete_job_page_is_rejected(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}/jobs']['total_count'] = 35
        self.check_blocked(d, 'INCOMPLETE_CI_JOBS')

    def test_different_sha_checked_out_by_required_job_is_rejected(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}/jobs']['jobs'][0]['head_sha'] = BASE
        self.check_blocked(d, 'REQUIRED_CI_JOBS_NOT_VERIFIED')

    def test_duplicate_job_names_are_rejected(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}/jobs']['jobs'][1]['name'] = 'offline-prototype-smoke'
        self.check_blocked(d, 'AMBIGUOUS_CI_JOBS')

    def test_invalid_sha_and_bad_run_type_refused_before_api(self):
        d = fixture()
        with self.assertRaises(AdmissionBlocked) as e:
            call(d, expected='HEAD')
        self.assertEqual(str(e.exception), 'INVALID_EXPECTED_HEAD')
        with self.assertRaises(AdmissionBlocked) as e:
            call(d, run=True)
        self.assertEqual(str(e.exception), 'INVALID_CI_RUN_ID')

    def test_wrong_ci_event_refused(self):
        d = fixture()
        d[f'/repos/{REPO}/actions/runs/{RUN}']['event'] = 'push'
        self.check_blocked(d, 'CI_NOT_VERIFIED_ON_EXACT_HEAD')

    def test_compare_commits_revision_mismatch_refused(self):
        d = fixture()
        d[f'/repos/{REPO}/compare/{BASE}...{HEAD}']['commits'][0]['sha'] = 'a'*40
        self.check_blocked(d, 'INCOMPLETE_COMPARE_EVIDENCE')


if __name__ == '__main__':
    unittest.main()
