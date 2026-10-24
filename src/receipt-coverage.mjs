import { createHash } from 'node:crypto';

const digest = value => createHash('sha256').update(value).digest('hex');
const sha40 = /^[a-f0-9]{40}$/u;
const sha256 = /^[a-f0-9]{64}$/u;
const outcomes = new Set(['NO_ACTIONABLE_FINDINGS','CHANGES_REQUESTED','INCONCLUSIVE']);
const error = code => { throw new Error(code); };
const unique = items => new Set(items).size === items.length;

/**
 * Checks metadata completeness of an immutable old/new source manifest.
 * This is NOT a source fetcher or verification of GitHub-issued blob objects.
 * A separate, trusted Git-object reader must establish source provenance.
 */
function verifyManifest(manifest) {
  if (!manifest || manifest.version !== 1 ||
      !sha40.test(manifest.baseSha ?? '') || !sha40.test(manifest.headSha ?? '') ||
      manifest.baseSha === manifest.headSha ||
      !Array.isArray(manifest.files) || manifest.files.length < 1 || manifest.files.length > 500 ||
      manifest.fileCount !== manifest.files.length ||
      !Array.isArray(manifest.shards) || manifest.shards.length < 1 || manifest.shards.length > 500 ||
      !sha256.test(manifest.manifestSha256 ?? '') ||
      manifest.manifestSha256 !== digest(JSON.stringify({...manifest,manifestSha256:null})))
    error('AI09_MANIFEST_SCOPE_INVALID');

  const slices = new Map();
  const paths = new Set();
  let bytes = 0;
  for (const file of manifest.files) {
    if (!file || typeof file.path !== 'string' || !file.path || paths.has(file.path) ||
        !['added','deleted','modified','renamed'].includes(file.status) ||
        !Array.isArray(file.slices) ||
        (file.status === 'renamed' && (typeof file.previousPath !== 'string' || file.previousPath === file.path)) ||
        (file.status !== 'renamed' && file.previousPath !== undefined))
      error('AI09_FILE_MANIFEST_INVALID');
    paths.add(file.path);
    for (const side of ['before','after']) {
      const n = file[side+'Bytes'];
      const h = file[side+'Sha256'];
      if (!Number.isSafeInteger(n) || n < 0 || !(h === null || sha256.test(h ?? '')))
        error('AI09_FILE_SIDE_INVALID');
      const pieces = file.slices.filter(s => s?.side === side);
      let offset = 0;
      for (const item of pieces) {
        if (!Number.isSafeInteger(item.id) || item.id < 1 || slices.has(item.id) ||
            item.path !== file.path || !sha256.test(item.sha256 ?? '') ||
            !Number.isSafeInteger(item.start) || item.start !== offset ||
            !Number.isSafeInteger(item.end) || item.end <= item.start ||
            item.end-item.start > 4096)
          error('AI09_SLICE_SEQUENCE_INVALID');
        slices.set(item.id, item);
        offset = item.end;
      }
      if (offset !== n || (h === null && (n !== 0 || pieces.length)))
        error('AI09_FILE_BYTE_COVERAGE_MISSING');
      bytes += n;
    }
    if (file.slices.some(s => !s || !['before','after'].includes(s.side)))
      error('AI09_SLICE_SIDE_INVALID');
    if (file.status === 'added' && (file.beforeSha256 !== null || file.beforeBytes !== 0) ||
        file.status === 'deleted' && (file.afterSha256 !== null || file.afterBytes !== 0))
      error('AI09_FILE_STATUS_SIDE_INVALID');
  }
  if (bytes !== manifest.totalBytes || slices.size === 0 || slices.size > 4096)
    error('AI09_SOURCE_BYTES_MISMATCH');

  const scheduled = new Set();
  for (const [i, shard] of manifest.shards.entries()) {
    if (!shard || shard.id !== i+1 || !Array.isArray(shard.sliceIds) ||
        shard.sliceIds.length < 1 || shard.sliceIds.length > 24 ||
        !unique(shard.sliceIds) || shard.sliceIds.some(id => !slices.has(id) || scheduled.has(id)))
      error('AI09_SHARD_SCOPE_INVALID');
    const items=shard.sliceIds.map(id=>slices.get(id));
    const groupBytes=items.reduce((n,s)=>n+s.end-s.start,0);
    const fileCount=new Set(items.map(s=>s.path)).size;
    if (fileCount > 30 || groupBytes > 120*1024 ||
        groupBytes !== shard.bytes || fileCount !== shard.fileCount ||
        shard.digest !== digest(JSON.stringify({baseSha:manifest.baseSha,
          headSha:manifest.headSha,index:shard.id,slices:items})))
      error('AI09_SHARD_DIGEST_INVALID');
    shard.sliceIds.forEach(id=>scheduled.add(id));
  }
  if (scheduled.size !== slices.size) error('AI09_UNSCHEDULED_SLICES');
  return {slices};
}

/**
 * Resumable, deterministic advisory aggregation. Accept receipts in any order;
 * missing jobs always remain pending. Never returns GitHub APPROVED, complete
 * independent authentication, or deployment/merge authority.
 *
 * An API-supplied reviewerId or modelDigest is never a trusted identity.
 */
export function auditReviewReceipts(manifest, receipts, {expectedBaseSha,expectedHeadSha}={}) {
  const blocked = (reason, pendingShardIds=[]) => ({
    status:'BLOCKED',reason,pendingShardIds,githubApprovalSatisfied:false,
    independentReviewerAuthenticated:false,crossFileSecurityReviewVerified:false,
    mergeAuthorized:false,evidenceClass:'AI_ASSERTED',
  });
  try {
    const {slices}=verifyManifest(manifest);
    if (expectedBaseSha !== undefined && manifest.baseSha !== expectedBaseSha ||
        expectedHeadSha !== undefined && manifest.headSha !== expectedHeadSha)
      error('AI09_REVIEW_TARGET_MOVED');
    if (!Array.isArray(receipts) || receipts.length > manifest.shards.length)
      error('AI09_RECEIPT_LIST_INVALID');
    const received = new Map();
    for (const receipt of receipts) {
      const shard=manifest.shards[receipt?.shardId-1];
      if (!shard || received.has(receipt.shardId) ||
          receipt.baseSha !== manifest.baseSha || receipt.headSha !== manifest.headSha ||
          receipt.manifestSha256 !== manifest.manifestSha256 ||
          receipt.shardDigest !== shard.digest ||
          !/^[A-Za-z0-9_.:-]{2,80}$/u.test(receipt.reviewerId ?? '') ||
          receipt.reviewerId === 'Builder' || !outcomes.has(receipt.status) ||
          !Array.isArray(receipt.evaluatedSliceIds) ||
          !Array.isArray(receipt.sliceResults) ||
          receipt.evaluatedSliceIds.length !== shard.sliceIds.length ||
          receipt.sliceResults.length !== shard.sliceIds.length ||
          receipt.evidenceSha256 !== digest(JSON.stringify(receipt.sliceResults)))
        error('AI09_SHARD_RECEIPT_INVALID');
      let computedStatus='NO_ACTIONABLE_FINDINGS';
      for (let i=0;i<shard.sliceIds.length;i++) {
        const id=shard.sliceIds[i],record=receipt.sliceResults[i];
        if (receipt.evaluatedSliceIds[i] !== id || record?.sliceId !== id ||
            !slices.has(id) || !sha256.test(record.reviewSha256 ?? '') ||
            !sha256.test(record.requestSha256 ?? '') ||
            !sha256.test(record.responseSha256 ?? '') ||
            !outcomes.has(record.status) ||
            !Number.isSafeInteger(record.findingCount) ||
            record.findingCount < 0 || record.findingCount > 20 ||
            (record.status === 'NO_ACTIONABLE_FINDINGS' && record.findingCount !== 0) ||
            (record.status === 'CHANGES_REQUESTED' && record.findingCount === 0))
          error('AI09_SLICE_RECEIPT_INVALID');
        if (record.status === 'INCONCLUSIVE') computedStatus='INCONCLUSIVE';
        else if (record.status === 'CHANGES_REQUESTED' && computedStatus !== 'INCONCLUSIVE')
          computedStatus='CHANGES_REQUESTED';
      }
      if (receipt.status !== computedStatus) error('AI09_SHARD_VERDICT_CONTRADICTION');
      received.set(receipt.shardId,receipt);
    }
    const pendingShardIds=manifest.shards.filter(s=>!received.has(s.id)).map(s=>s.id);
    const sortedReceipts=[...received.values()].sort((a,b)=>a.shardId-b.shardId);
    const assessedSlices=sortedReceipts.reduce((n,r)=>n+r.evaluatedSliceIds.length,0);
    const statuses=sortedReceipts.map(r=>r.status);
    const status=pendingShardIds.length ? 'REVIEW_PARTIAL' :
      statuses.includes('INCONCLUSIVE') ? 'REVIEW_INCONCLUSIVE' :
      statuses.includes('CHANGES_REQUESTED') ? 'CHANGES_REQUESTED' :
      'SOURCE_SLICES_REVIEWED_ADVISORY_ONLY';
    return {
      status,baseSha:manifest.baseSha,headSha:manifest.headSha,
      manifestSha256:manifest.manifestSha256,
      fileCount:manifest.fileCount,shardCount:manifest.shards.length,
      totalSlices:slices.size,receivedShards:received.size,assessedSlices,
      pendingShardIds,advisoryLedgerSha256:digest(JSON.stringify(sortedReceipts)),
      githubApprovalSatisfied:false,independentReviewerAuthenticated:false,
      crossFileSecurityReviewVerified:false,mergeAuthorized:false,evidenceClass:'AI_ASSERTED',
    };
  } catch (e) {return blocked(/^AI09_[A-Z0-9_]+$/u.test(e?.message??'')?e.message:'AI09_RECEIPT_AUDIT_FAILED');}
}
