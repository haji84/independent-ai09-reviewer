#!/usr/bin/env python3
"""Read-only PUBLIC target admission; no model invocation, diff or token output."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from public_pr_scope import AdmissionBlocked, admit_public_pr


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verify authorized public PR, full diff and exact-head CI')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--pr', required=True, type=int)
    parser.add_argument('--expected-head', required=True)
    parser.add_argument('--ci-run', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        receipt = admit_public_pr(args.repo, args.pr, args.expected_head, args.ci_run).receipt()
        print(json.dumps(receipt, ensure_ascii=True, sort_keys=True))
        return 0
    except AdmissionBlocked as error:
        # Known stable codes only; never print GitHub responses, source or credentials.
        print('AI09_PUBLIC_ADMISSION=' + str(error) + '; MODEL_REVIEW=NOT_RUN; MERGE_AUTHORIZED=false')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
