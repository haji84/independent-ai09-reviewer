import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {sealPrivateModelFindings,openPrivateModelFindings} from '../src/private-findings.mjs';
import {parseSafePublicReview} from '../src/review-schema.mjs';
const H=x=>createHash('sha256').update(x).digest('hex');
const scope=raw=>({baseSha:'a'.repeat(40),headSha:'b'.repeat(40),reviewerSha:'c'.repeat(40),
 manifestSha256:H('manifest'),modelDigest:H('model'),sourceSha256:H('source'),
 promptSha256:H('prompt'),responseSha256:H(raw),
 path:'src/remote-lite/owner-auth.mjs',side:'after',start:100,end:102,sliceId:8});
const model='qwen2.5-coder:7b';
const finding={severity:'critical',summary:'Unsafe authorization header: private-token-xyz'};
const packet=()=>({model,done:true,done_reason:'stop',message:{content:JSON.stringify({
 verdict:'CHANGES_REQUESTED',findings:[finding]})}});
test('public evidence is digest-only while encrypted detail can be privately recovered',()=>{
 const p=packet(),key=randomBytes(32),s=scope(p.message.content);
 const pub=parseSafePublicReview(p,model);
 assert.equal(pub.findings[0].summarySha256,H(finding.summary));
 assert.equal(JSON.stringify(pub).includes('private-token'),false);
 const env=sealPrivateModelFindings(p,model,s,key);
 assert.equal(JSON.stringify(env).includes('private-token'),false);
 assert.deepEqual(openPrivateModelFindings(env,s,key),{verdict:'CHANGES_REQUESTED',findings:[finding]});
});
test('wrong key, tampering and different source scope refuse recovery',()=>{
 const p=packet(),key=randomBytes(32),s=scope(p.message.content);
 const env=sealPrivateModelFindings(p,model,s,key);
 assert.throws(()=>openPrivateModelFindings(env,s,randomBytes(32)),/PRIVATE_AUTH_FAILED/u);
 const changed={...env,ciphertext:env.ciphertext.slice(0,-1)+(env.ciphertext.endsWith('A')?'B':'A')};
 assert.throws(()=>openPrivateModelFindings(changed,s,key),/PRIVATE_AUTH_FAILED|PRIVATE_FORMAT_INVALID/u);
 assert.throws(()=>openPrivateModelFindings(env,{...s,headSha:'d'.repeat(40)},key),/PRIVATE_SCOPE_OR_FORMAT_INVALID/u);
});
test('contradictory model verdict and forged response digest are rejected',()=>{
 const p=packet(),key=randomBytes(32),s=scope(p.message.content);
 assert.throws(()=>sealPrivateModelFindings(p,model,{...s,responseSha256:H('wrong')},key),/RESPONSE_DIGEST_MISMATCH/u);
 const bad={...p,message:{content:JSON.stringify({verdict:'NO_FINDINGS',findings:[finding]})}};
 assert.throws(()=>sealPrivateModelFindings(bad,model,scope(bad.message.content),key),/RESPONSE_SCHEMA_INVALID/u);
});
