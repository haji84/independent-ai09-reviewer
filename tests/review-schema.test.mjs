import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {parseSafePublicReview} from '../src/review-schema.mjs';
const model='qwen2.5-coder:7b',H=x=>createHash('sha256').update(x).digest('hex');
const packet=obj=>({model,done:true,done_reason:'stop',message:{content:JSON.stringify(obj)}});
const finding={severity:'high',summary:'Authorization: Bearer synthetic-token-12345678'};
test('clean answer remains advisory with no sensitive content',()=>{
  assert.deepEqual(parseSafePublicReview(packet({verdict:'NO_FINDINGS',findings:[]}),model),{verdict:'NO_FINDINGS',findings:[]});
});
test('unsafe contradictory verdicts always reject',()=>{
  for(const o of [
    {verdict:'NO_FINDINGS',findings:[finding]},
    {verdict:'CHANGES_REQUESTED',findings:[]},
  ]) assert.throws(()=>parseSafePublicReview(packet(o),model),/AI09_RESPONSE_SCHEMA_INVALID/);
});
test('public evidence contains SHA only, never untrusted model summary',()=>{
  const x=parseSafePublicReview(packet({verdict:'CHANGES_REQUESTED',findings:[finding]}),model);
  assert.deepEqual(x.findings,[{severity:'high',summarySha256:H(finding.summary)}]);
  assert.equal(JSON.stringify(x).includes('synthetic-token'),false);
});
test('partial, wrong-model, oversized, malformed and unexpected shapes reject',()=>{
  for(const bad of [
    {...packet({verdict:'NO_FINDINGS',findings:[]}),done:false},
    {...packet({verdict:'NO_FINDINGS',findings:[]}),done_reason:'length'},
    {...packet({verdict:'NO_FINDINGS',findings:[]}),model:'other'},
    {...packet({verdict:'NO_FINDINGS',findings:[]}),message:{content:'broken{'}},
    {...packet({verdict:'NO_FINDINGS',findings:[]}),message:{content:'x'.repeat(16001)}},
    packet({verdict:'NO_FINDINGS',findings:[],other:true}),
    packet({verdict:'CHANGES_REQUESTED',findings:[{...finding,summary:'line\nbreak'}]}),
    packet({verdict:'CHANGES_REQUESTED',findings:[{...finding,severity:'invalid'}]}),
  ]) assert.throws(()=>parseSafePublicReview(bad,model),/AI09_RESPONSE_(?:INVALID|NON_JSON|SCHEMA_INVALID)/);
});
