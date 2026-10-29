#!/usr/bin/env python3
"""Eight observed real-model calls on PUBLIC data; no private activation."""
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pilot_host

# Keep the previously tested helper surface while sharing the implementation.
validate_public_packet = pilot_host.validate_public_packet
staged_batch = pilot_host.staged_batch
SAFE_ERRORS = pilot_host.SAFE_ERRORS


def experiment():
    # The shared preparation receives neither private inputs nor a key. Only the
    # fixed PUBLIC entrypoint below is reachable from this CLI/workflow.
    with pilot_host.prepare_runtime() as prepared:
        print('PUBLIC_MODEL_PHASE=VERIFIED_CPU_SELECTION', flush=True)
        with tempfile.TemporaryDirectory(prefix='ai09-public-evidence-') as directory:
            output = pathlib.Path(directory); output.chmod(0o700)
            print('PUBLIC_MODEL_PHASE=OFFLINE_INFERENCE', flush=True)
            result = pilot_host.run_public_pilot(prepared,
                run_id=os.environ['GITHUB_RUN_ID'],
                attempt=int(os.environ.get('GITHUB_RUN_ATTEMPT', '1')),
                commit=os.environ['GITHUB_SHA'], output_directory=output)
        # The actual ciphertext was reopened/authenticated/semantically verified
        # inside the controller, and the temporary PUBLIC output is now removed.
        print('PUBLIC_MODEL_LAUNCH_SHA256='+result.launch_sha256)
        print('PUBLIC_MODEL_RECEIPT_SHA256='+result.packet_sha256)
        print('PUBLIC_ENCRYPTED_EVIDENCE_SHA256='+result.ciphertext_sha256)
        print('PUBLIC_EVIDENCE_ROUNDTRIP=PASS; OBSERVED_RESPONSES=8; FIXED_SUBJECT_RECEIPTS=0')
        print('PUBLIC_EVIDENCE_FILE_READBACK=PASS; CIPHERTEXT_BYTES='+str(result.ciphertext_bytes))
        print('PUBLIC_CONTEXT_REJECTION_SHA256='+result.context_rejection_sha256)
        print('PUBLIC_CONTEXT_REJECTION=PASS; HTTP_STATUS=400; PROMPT_TOKENS='+
              str(result.context_rejection_tokens)+'; CONTEXT_TOKENS=4096; FIXED_SUBJECT_RECEIPTS=0')
        print('PUBLIC_MODEL_ELAPSED_SECONDS='+str(result.elapsed_seconds))


def main():
    try:
        experiment()
    except BaseException as error:
        code = str(error) if str(error) in SAFE_ERRORS else 'UNEXPECTED_ERROR'
        print('PUBLIC_MODEL_ERROR='+code)
        print('PUBLIC_MODEL_SMOKE=FAIL; FIXED_SUBJECT_RECEIPTS=0; DESIGN_APPROVAL=HOLD')
        return 2
    print('PUBLIC_MODEL_SMOKE=PASS; PUBLIC_TOY_MODEL_CALLS=8; FIXED_SUBJECT_RECEIPTS=0; DESIGN_APPROVAL=HOLD')
    return 0


if __name__ == '__main__': raise SystemExit(main())
