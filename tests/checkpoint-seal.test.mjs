import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {mkdtempSync,rmSync,readFileSync,writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {sealReviewCheckpoint,openReviewCheckpoint} from '../src/checkpoint-seal.mjs';
const hash=v=>createHash('sha256').update(v).digest('hex');
const reviewerSha='c'.repeat(40),baseSha='a'.repeat(40),headSha='b'.repeat(40);
function fixture(){
  const path='src/remote-lite/a.mjs';
  const piece={id:1,path,side:'after',start:0,end:1,sha256:hash('x')};
  const file={path,status:'added',beforeBytes:0,afterBytes:1,beforeSha256:null,
    afterSha256:hash('x'),slices:[piece]};
  const shard={id:1,digest:hash(JSON.stringify({baseSha,headSha,index:1,slices:[piece]})),
    sliceIds:[1],fileCount:1,bytes:1};
  const manifest={version:1,baseSha,headSha,fileCount:1,totalBytes:1,
    files:[file],shards:[shard],manifestSha256:null};
  manifest.manifestSha256=hash(JSON.stringify({...manifest,manifestSha256:null}));
  const sliceResults=[{sliceId:1,reviewSha256:hash('review'),requestSha256:hash('req'),
    responseSha256:hash('resp'),status:'NO_ACTIONABLE_FINDINGS',findingCount:0}];
  const receipt={shardId:1,shardDigest:shard.digest,manifestSha256:manifest.manifestSha256,
    baseSha,headSha,reviewerId:'AI09-reviewer',status:'NO_ACTIONABLE_FINDINGS',
    evaluatedSliceIds:[1],sliceResults,evidenceSha256:hash(JSON.stringify(sliceResults))};
  return {manifest,receipt};
}

test('checkpoint is encrypted, resumable and never an approval',()=>{
  const {manifest,receipt}=fixture(),key=randomBytes(32);
  const sealed=sealReviewCheckpoint(manifest,[receipt],reviewerSha,key);
  assert.equal(JSON.stringify(sealed).includes('AI09-reviewer'),false);
  const opened=openReviewCheckpoint(sealed,manifest,reviewerSha,key);
  assert.deepEqual(opened.receipts,[receipt]);
  assert.equal(opened.state.status,'SOURCE_SLICES_REVIEWED_ADVISORY_ONLY');
  assert.equal(opened.state.mergeAuthorized,false);
});
test('wrong key, corrupted ciphertext, stale reviewer and target all reject',()=>{
  const {manifest,receipt}=fixture(),key=randomBytes(32);
  const sealed=sealReviewCheckpoint(manifest,[receipt],reviewerSha,key);
  assert.throws(()=>openReviewCheckpoint(sealed,manifest,reviewerSha,randomBytes(32)),/AUTH_FAILED/u);
  const flip=sealed.ciphertext.slice(0,-1)+(sealed.ciphertext.endsWith('A')?'B':'A');
  assert.throws(()=>openReviewCheckpoint({...sealed,ciphertext:flip},manifest,reviewerSha,key),/AUTH_FAILED/u);
  assert.throws(()=>openReviewCheckpoint(sealed,manifest,'d'.repeat(40),key),/SCOPE_OR_FORMAT_INVALID/u);
  assert.throws(()=>openReviewCheckpoint(sealed,{...manifest,headSha:'d'.repeat(40)},reviewerSha,key),/SCOPE_OR_FORMAT_INVALID/u);
});
test('raw source, surprise fields and invalid proof refuse sealing',()=>{
  const {manifest,receipt}=fixture(),key=randomBytes(32);
  assert.throws(()=>sealReviewCheckpoint(manifest,[{...receipt,prompt:'secret'}],reviewerSha,key),/SENSITIVE/u);
  assert.throws(()=>sealReviewCheckpoint(manifest,[{...receipt,status:'CHANGES_REQUESTED'}],reviewerSha,key),/RECEIPTS_INVALID/u);
  assert.throws(()=>sealReviewCheckpoint(manifest,[receipt],reviewerSha,Buffer.alloc(8)),/KEY_INVALID/u);
});
test('separate Node processes restore an encrypted checkpoint without persisted key',()=>{
  const {manifest,receipt}=fixture(),key=randomBytes(32),dir=mkdtempSync(join(tmpdir(),'ai09-sealed-'));
  const moduleUrl=new URL('../src/checkpoint-seal.mjs',import.meta.url).href;
  const args=JSON.stringify({manifest,receipt,reviewerSha,key:key.toString('hex')});
  try{
    const sealScript=`import {sealReviewCheckpoint} from ${JSON.stringify(moduleUrl)};
      const i=JSON.parse(process.env.AI09_TEST_FIXTURE);
      process.stdout.write(JSON.stringify(sealReviewCheckpoint(i.manifest,[i.receipt],i.reviewerSha,Buffer.from(i.key,'hex'))));`;
    const first=spawnSync(process.execPath,['--input-type=module','-e',sealScript],
      {encoding:'utf8',env:{...process.env,AI09_TEST_FIXTURE:args}});
    assert.equal(first.status,0,first.stderr);
    writeFileSync(join(dir,'checkpoint.enc.json'),first.stdout,{mode:0o600});
    const restoreScript=`import {openReviewCheckpoint} from ${JSON.stringify(moduleUrl)};
      const i=JSON.parse(process.env.AI09_TEST_FIXTURE);
      const envelope=JSON.parse(process.stdin.read()??'null');
      const r=openReviewCheckpoint(envelope,i.manifest,i.reviewerSha,Buffer.from(i.key,'hex'));
      process.stdout.write(r.state.status);`;
    // Second process receives the envelope over stdin, not from mutable source or repository code.
    const second=spawnSync(process.execPath,['--input-type=module','-e',
      restoreScript.replace("process.stdin.read()??'null'","await new Promise((resolve,reject)=>{let s='';process.stdin.setEncoding('utf8');process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>resolve(s));process.stdin.on('error',reject)})")],
      {encoding:'utf8',input:readFileSync(join(dir,'checkpoint.enc.json'),'utf8'),
        env:{...process.env,AI09_TEST_FIXTURE:args}});
    assert.equal(second.status,0,second.stderr);
    assert.equal(second.stdout,'SOURCE_SLICES_REVIEWED_ADVISORY_ONLY');
  }finally{rmSync(dir,{recursive:true,force:true})}
});
