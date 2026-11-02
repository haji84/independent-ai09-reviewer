"""Read-only, fail-closed admission for PUBLIC GitHub PRs to the existing AI09 engine.

Only metadata/provenance. Never executes the PR source, calls a model, exports a
patch or authorizes a merge. GORIQ's existing AI09 model/review core is separate.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Mapping
import json
import re
from urllib.request import Request, urlopen

REPO_RE = re.compile(r"^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")
PATH_RE = re.compile(r"^[a-zA-Z0-9_./-]+\.yml$")
MAX_FILES = 30
MAX_PATCH_BYTES = 120 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_COMMITS = 250
# Explicit initial public target; add others only after their own privacy/CI review.
PUBLIC_TARGETS = {
    "haji84/AI-VIDEO-STUDIO": {
        "workflows": frozenset({".github/workflows/manual-smoke.yml"}),
        "required_jobs": frozenset({"offline-prototype-smoke", "synthetic-browser-acceptance"}),
    },
}


class AdmissionBlocked(ValueError):
    """A stable error code, never source/response bytes or model text."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise AdmissionBlocked(code)


def _safe_dict(value: object) -> dict:
    _require(type(value) is dict, "MALFORMED_GITHUB_RESPONSE")
    return value


def _repo_of(obj: object) -> str | None:
    return obj.get("full_name") if type(obj) is dict else None


def public_get(path: str) -> dict:
    """Tokenless API read. Limited size, host, timeout; never log response bodies."""
    _require(path.startswith("/repos/") and "?" not in path and "#" not in path,
             "INVALID_PUBLIC_API_PATH")
    uri = "https://api.github.com" + path
    request = Request(uri, headers={"Accept": "application/vnd.github+json",
        "User-Agent": "ai09-public-readonly-admission", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with urlopen(request, timeout=15) as response:
            _require(response.status == 200 and response.geturl() == uri, "GITHUB_API_UNAVAILABLE")
            length = response.headers.get("Content-Length")
            _require(length is None or (length.isdecimal() and int(length) <= MAX_RESPONSE_BYTES),
                     "GITHUB_RESPONSE_TOO_LARGE")
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except AdmissionBlocked:
        raise
    except (OSError, ValueError):
        raise AdmissionBlocked("GITHUB_API_UNAVAILABLE") from None
    _require(len(payload) <= MAX_RESPONSE_BYTES, "GITHUB_RESPONSE_TOO_LARGE")
    try:
        data = json.loads(payload)
    except (UnicodeDecodeError, ValueError):
        raise AdmissionBlocked("MALFORMED_GITHUB_RESPONSE") from None
    return _safe_dict(data)


@dataclass(frozen=True, repr=False)
class PublicReviewTarget:
    repository: str
    pr_number: int
    base_sha: str
    head_sha: str
    ci_run_id: int
    ci_path: str
    changed_paths: tuple[str, ...]
    patch_sha256: str
    patch_bytes: int
    # Deliberately never include raw patch bytes in public receipts.

    def receipt(self) -> dict:
        return {"schema": "ai09-public-target-v1", "repository": self.repository,
                "pr_number": self.pr_number, "base_sha": self.base_sha,
                "head_sha": self.head_sha, "ci_run_id": self.ci_run_id,
                "ci_path": self.ci_path, "paths": list(self.changed_paths),
                "patch_sha256": self.patch_sha256, "patch_bytes": self.patch_bytes,
                "admission": "PUBLIC_SOURCE_VERIFIED", "independent_model_review": "NOT_RUN",
                "github_approval_satisfied": False, "merge_authorized": False}


def admit_public_pr(repository: str, pr_number: int, expected_head: str,
                    ci_run_id: int, *, get: Callable[[str], dict] = public_get,
                    targets: Mapping[str, dict] = PUBLIC_TARGETS) -> PublicReviewTarget:
    """Validate PR, public repo, exact current HEAD, complete diff, successful CI.

    The returned receipt is only an input-admission statement, not an AI review.
    No network action can write, download private blobs, run PR code, or post.
    """
    _require(type(repository) is str and REPO_RE.fullmatch(repository) is not None,
             "INVALID_REPOSITORY")
    _require(repository in targets, "REPOSITORY_NOT_APPROVED")
    policy = targets[repository]
    _require(type(policy) is dict and
             type(policy.get("workflows")) is frozenset and policy["workflows"] and
             type(policy.get("required_jobs")) is frozenset and policy["required_jobs"],
             "INVALID_TARGET_POLICY")
    _require(type(pr_number) is int and 1 <= pr_number <= 1_000_000_000,
             "INVALID_PR_NUMBER")
    _require(type(ci_run_id) is int and 1 <= ci_run_id <= 2**63 - 1,
             "INVALID_CI_RUN_ID")
    _require(type(expected_head) is str and SHA_RE.fullmatch(expected_head) is not None,
             "INVALID_EXPECTED_HEAD")
    base = "/repos/" + repository
    repo = _safe_dict(get(base))
    _require(repo.get("full_name") == repository and repo.get("private") is False and
             repo.get("visibility") == "public" and not repo.get("fork", False),
             "TARGET_NOT_VERIFIED_PUBLIC")
    pr = _safe_dict(get(base + "/pulls/" + str(pr_number)))
    head = _safe_dict(pr.get("head")); target = _safe_dict(pr.get("base"))
    head_sha, base_sha = head.get("sha"), target.get("sha")
    _require(pr.get("number") == pr_number and pr.get("state") == "open" and
             head_sha == expected_head and type(base_sha) is str and SHA_RE.fullmatch(base_sha) and
             base_sha != head_sha and _repo_of(head.get("repo")) == repository and
             _repo_of(target.get("repo")) == repository and
             target.get("ref") == repo.get("default_branch") and
             type(head.get("ref")) is str and 0 < len(head["ref"]) <= 180,
             "STALE_OR_FOREIGN_PR")
    changed = pr.get("changed_files")
    _require(type(changed) is int and 1 <= changed <= MAX_FILES, "UNREVIEWABLE_PR_SIZE")
    ci = _safe_dict(get(base + "/actions/runs/" + str(ci_run_id)))
    _require(ci.get("id") == ci_run_id and ci.get("status") == "completed" and
             ci.get("conclusion") == "success" and ci.get("head_sha") == expected_head and
             ci.get("head_branch") == head["ref"] and
             _repo_of(ci.get("repository")) == repository and
             ci.get("event") in {"pull_request", "workflow_dispatch"} and
             ci.get("path") in policy["workflows"] and
             type(ci.get("run_attempt")) is int and ci["run_attempt"] >= 1,
             "CI_NOT_VERIFIED_ON_EXACT_HEAD")
    job_response = _safe_dict(get(base + "/actions/runs/" + str(ci_run_id) + "/jobs"))
    jobs = job_response.get("jobs")
    total_jobs = job_response.get("total_count")
    _require(type(total_jobs) is int and 1 <= total_jobs <= 30 and
             type(jobs) is list and len(jobs) == total_jobs, "INCOMPLETE_CI_JOBS")
    by_name = {}
    for job in jobs:
        j = _safe_dict(job)
        name = j.get("name")
        _require(type(name) is str and name not in by_name, "AMBIGUOUS_CI_JOBS")
        by_name[name] = j
    _require(all(name in by_name and by_name[name].get("status") == "completed" and
                 by_name[name].get("conclusion") == "success" and
                 by_name[name].get("head_sha") == expected_head
                 for name in policy["required_jobs"]), "REQUIRED_CI_JOBS_NOT_VERIFIED")
    comp = _safe_dict(get(base + "/compare/" + base_sha + "..." + expected_head))
    files = comp.get("files"); commits = comp.get("commits")
    _require(comp.get("status") in {"ahead", "diverged"} and
             _safe_dict(comp.get("base_commit")).get("sha") == base_sha and
             type(comp.get("total_commits")) is int and 1 <= comp["total_commits"] <= MAX_COMMITS and
             type(commits) is list and len(commits) == comp["total_commits"] and
             _safe_dict(commits[-1]).get("sha") == expected_head and
             type(files) is list and len(files) == changed,
             "INCOMPLETE_COMPARE_EVIDENCE")
    paths: list[str] = []
    fragments: list[str] = []
    for file in files:
        f = _safe_dict(file)
        name, patch = f.get("filename"), f.get("patch")
        _require(type(name) is str and 0 < len(name) <= 250 and
                 not name.startswith(("-", "/")) and "\\" not in name and
                 all(part not in {"", ".", ".."} for part in name.split("/")) and
                 all(32 <= ord(char) < 127 for char in name) and
                 type(patch) is str and patch.startswith("@@") and
                 f.get("status") in {"added", "modified", "removed", "renamed"},
                 "UNREVIEWABLE_PATCH_FILE")
        paths.append(name)
        fragments.append("diff --git a/" + name + " b/" + name + "\n" + patch)
    _require(len(set(paths)) == len(paths), "DUPLICATE_CHANGED_PATH")
    body = "\n".join(fragments).encode("utf-8")
    _require(0 < len(body) <= MAX_PATCH_BYTES, "REVIEW_PATCH_BUDGET_EXCEEDED")
    return PublicReviewTarget(repository, pr_number, base_sha, head_sha,
                              ci_run_id, ci["path"], tuple(paths),
                              sha256(body).hexdigest(), len(body))
