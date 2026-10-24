import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,symlinkSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {writeReviewReceipt,readReviewLedger} from '../src/receipt-ledger.mjs';
const H=x=>createHash('sha256').update(x).digest('hex');
const baseSha='a'.repeat(40),headSha='b'.repeat(40);
function fixture(){
  const path='a.mjs',parts=[{id:1,path,side:'after',start:0,end:1,sha256:H('x')}];
  const file={path,status:'added',beforeBytes:0,afterBytes:1,beforeSha256:null,afterSha256:H('x'),slices:parts};
  const shard={id:1,digest:H(JSON.stringify({baseSha,headSha,index:1,slices:parts})),sliceIds:[1],fileCount:1,bytes:1};
  const manifest={version:1,baseSha,headSha,fileCount:1,totalBytes:1,files:[file],shards:[shard],manifestSha256:null};
  manifest.manifestSha256=H(JSON.stringify({...manifest,manifestSha256:null}));
  const slices=[{sliceId:1,reviewSha256:H('r'),requestSha256:H('q'),responseSha256:H('a'),status:'NO_ACTIONABLE_FINDINGS',findingCount:0}];
  const receipt={shardId:1,shardDigest:shard.digest,manifestSha256:manifest.manifestSha256,
    baseSha,headSha,reviewerId:'AI09-separate',status:'NO_ACTIONABLE_FINDINGS',evaluatedSliceIds:[1],
    sliceResults:slices,evidenceSha256:H(JSON.stringify(slices))};
  return {manifest,receipt};
}
function withDir(fn){const d=mkdtempSync(join(tmpdir(),'ai09-ledger-'));try{return fn(d)}finally{rmSync(d,{recursive:true,force:true})}}
test('receipt persists and reopens only as advisory, never authentic approval',()=>withDir(dir=>{
  const {manifest,receipt}=fixture();
  assert.equal(writeReviewReceipt(dir,manifest,receipt).stored,true);
  const a=readReviewLedger(dir,manifest);
  assert.equal(a.status,'SOURCE_SLICES_REVIEWED_ADVISORY_ONLY');
  assert.equal(a.githubApprovalSatisfied,false);
  assert.equal(a.mergeAuthorized,false);
  assert.throws(()=>writeReviewReceipt(dir,manifest,receipt),/EEXIST/u);
}));
test('raw source and surprise fields cannot enter publicizable receipt files',()=>withDir(dir=>{
  const {manifest,receipt}=fixture();
  assert.throws(()=>writeReviewReceipt(dir,manifest,{...receipt,prompt:'secret text'}),/SENSITIVE/u);
  assert.throws(()=>writeReviewReceipt(dir,manifest,{...receipt,sliceResults:[{...receipt.sliceResults[0],text:'raw source'}]}),/SENSITIVE/u);
}));
test('tampered saved record and unexpected file both block recovery',()=>withDir(dir=>{
  const {manifest,receipt}=fixture();
  writeReviewReceipt(dir,manifest,receipt);
  const path=join(dir,'shard-1.json'),saved=JSON.parse(readFileSync(path,'utf8'));
  saved.sliceResults[0].responseSha256='f'.repeat(64);
  writeFileSync(path,JSON.stringify(saved));
  assert.equal(readReviewLedger(dir,manifest).status,'BLOCKED');
  writeFileSync(join(dir,'other.txt'),'secret');
  assert.throws(()=>readReviewLedger(dir,manifest),/UNEXPECTED_FILE/u);
}));
test('symlink is rejected, partial ledger remains incomplete',()=>withDir(dir=>{
  const {manifest}=fixture();
  assert.equal(readReviewLedger(dir,manifest).status,'REVIEW_PARTIAL');
  symlinkSync('/nonexistent/path',join(dir,'shard-1.json'));
  assert.throws(()=>readReviewLedger(dir,manifest),/FILE_UNSAFE/u);
}));
