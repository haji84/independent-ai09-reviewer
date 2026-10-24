import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { auditReviewReceipts } from '../src/receipt-coverage.mjs';

const h=x=>createHash('sha256').update(x).digest('hex');
const baseSha='a'.repeat(40),headSha='b'.repeat(40);
function fixture({files=217,slicesPerFile=4}={}) {
  let id=0;
  const records=Array.from({length:files},(_,i)=>{
    const path='src/remote-lite/file-'+i+'.mjs';
    const slices=Array.from({length:slicesPerFile},(_,j)=>{
      const n=++id;return {id:n,path,side:'after',start:j*100,end:(j+1)*100,sha256:h('slice:'+n)};
    });
    return {path,status:'added',beforeBytes:0,afterBytes:100*slicesPerFile,
      beforeSha256:null,afterSha256:h('source:'+i),slices};
  });
  const all=records.flatMap(f=>f.slices);
  const shards=[];
  for(let i=0;i<all.length;i+=24) {
    const slices=all.slice(i,i+24),index=shards.length+1;
    shards.push({id:index,digest:h(JSON.stringify({baseSha,headSha,index,slices})),
      sliceIds:slices.map(s=>s.id),bytes:slices.length*100,
      fileCount:new Set(slices.map(s=>s.path)).size});
  }
  const manifest={version:1,baseSha,headSha,fileCount:files,totalBytes:all.length*100,
    files:records,shards,manifestSha256:null};
  manifest.manifestSha256=h(JSON.stringify({...manifest,manifestSha256:null}));
  function receipt(shard,kind='NO_ACTIONABLE_FINDINGS') {
    const items=shard.sliceIds.map(id=>({sliceId:id,reviewSha256:h('review:'+id),
      requestSha256:h('request:'+id),responseSha256:h('response:'+id),
      status:kind,findingCount:kind==='CHANGES_REQUESTED'?1:0}));
    return {shardId:shard.id,shardDigest:shard.digest,manifestSha256:manifest.manifestSha256,
      baseSha,headSha,reviewerId:'AI09-separate-model',status:kind,
      evaluatedSliceIds:shard.sliceIds.slice(),sliceResults:items,evidenceSha256:h(JSON.stringify(items))};
  }
  return {manifest,receipt};
}

test('no hard-coded 33-shard ceiling and all distinct receipts validate as advisory only',()=>{
  const {manifest,receipt}=fixture({files:217,slicesPerFile:5});
  assert.ok(manifest.shards.length>33);
  const all=manifest.shards.map(s=>receipt(s));
  const result=auditReviewReceipts(manifest,all.reverse(),{expectedBaseSha:baseSha,expectedHeadSha:headSha});
  assert.equal(result.status,'SOURCE_SLICES_REVIEWED_ADVISORY_ONLY');
  assert.equal(result.assessedSlices,217*5);
  assert.equal(result.shardCount,manifest.shards.length);
  assert.equal(result.receivedShards,manifest.shards.length);
  assert.equal(result.githubApprovalSatisfied,false);
  assert.equal(result.independentReviewerAuthenticated,false);
  assert.equal(result.crossFileSecurityReviewVerified,false);
  assert.equal(result.mergeAuthorized,false);
});

test('restart/resume reports every missing shard without turning partial progress green',()=>{
  const {manifest,receipt}=fixture();
  const r=auditReviewReceipts(manifest,[receipt(manifest.shards[0]),receipt(manifest.shards.at(-1))]);
  assert.equal(r.status,'REVIEW_PARTIAL');
  assert.equal(r.receivedShards,2);
  assert.equal(r.pendingShardIds.length,manifest.shards.length-2);
  assert.ok(!r.pendingShardIds.includes(1));
  assert.ok(!r.pendingShardIds.includes(manifest.shards.length));
});

test('duplicate, forged digest and shifted HEAD are rejected',()=>{
  const {manifest,receipt}=fixture();
  const r=receipt(manifest.shards[0]);
  assert.equal(auditReviewReceipts(manifest,[r,r]).status,'BLOCKED');
  assert.equal(auditReviewReceipts(manifest,[{...r,shardDigest:'f'.repeat(64)}]).status,'BLOCKED');
  assert.equal(auditReviewReceipts(manifest,[r],{expectedHeadSha:'c'.repeat(40)}).reason,'AI09_REVIEW_TARGET_MOVED');
});

test('missing slices or response hash always block, including a recomputed receipt digest',()=>{
  const {manifest,receipt}=fixture();
  const r=receipt(manifest.shards[0]);
  r.sliceResults.pop();
  r.evidenceSha256=h(JSON.stringify(r.sliceResults));
  assert.equal(auditReviewReceipts(manifest,[r]).reason,'AI09_SHARD_RECEIPT_INVALID');
  const s=receipt(manifest.shards[0]);
  s.sliceResults[0].responseSha256='bad';s.evidenceSha256=h(JSON.stringify(s.sliceResults));
  assert.equal(auditReviewReceipts(manifest,[s]).reason,'AI09_SLICE_RECEIPT_INVALID');
});

test('INCONCLUSIVE, actionable findings and contradictory statuses cannot appear clean',()=>{
  const {manifest,receipt}=fixture({files:2});
  const shard=manifest.shards[0];
  assert.equal(auditReviewReceipts(manifest,[receipt(shard,'INCONCLUSIVE')]).status,'REVIEW_INCONCLUSIVE');
  assert.equal(auditReviewReceipts(manifest,[receipt(shard,'CHANGES_REQUESTED')]).status,'CHANGES_REQUESTED');
  const r=receipt(shard);
  r.sliceResults[0].status='CHANGES_REQUESTED';r.sliceResults[0].findingCount=1;
  r.evidenceSha256=h(JSON.stringify(r.sliceResults));
  assert.equal(auditReviewReceipts(manifest,[r]).reason,'AI09_SHARD_VERDICT_CONTRADICTION');
});

test('tampered source-side range and shard digest fail even when manifest root rehashed',()=>{
  const {manifest}=fixture({files:2});
  manifest.files[0].slices[0].start=1;
  manifest.manifestSha256=h(JSON.stringify({...manifest,manifestSha256:null}));
  assert.equal(auditReviewReceipts(manifest,[]).reason,'AI09_SLICE_SEQUENCE_INVALID');
  const other=fixture({files:2}).manifest;
  other.shards[0].digest='f'.repeat(64);
  other.manifestSha256=h(JSON.stringify({...other,manifestSha256:null}));
  assert.equal(auditReviewReceipts(other,[]).reason,'AI09_SHARD_DIGEST_INVALID');
});
