import test from 'node:test';
import assert from 'node:assert/strict';
import {parseAdvisoryPacket} from '../src/model-advisory-gemma.mjs';
const pkt=o=>({model:'gemma3:1b',done:true,done_reason:'stop',
 message:{content:JSON.stringify(o)}});
const paths={'src/checkpoint-seal.mjs':88};
test('distinct-model structured findings retain path and line without free text',()=>{
 const d=parseAdvisoryPacket(pkt({verdict:'CHANGES_REQUESTED',findings:[
  {path:'src/checkpoint-seal.mjs',line:41,category:'CHECKPOINT_ROLLBACK',severity:'high'}
 ]}),paths);
 assert.equal(d.findings[0].line,41);
 assert.equal(JSON.stringify(d).includes('password'),false);
});
test('fake paths and contradictory verdicts are rejected',()=>{
 for(const o of [
  {verdict:'NO_FINDINGS',findings:[{path:'src/checkpoint-seal.mjs',line:1,category:'AUTH',severity:'high'}]},
  {verdict:'CHANGES_REQUESTED',findings:[]},
  {verdict:'INCONCLUSIVE',findings:[{path:'src/checkpoint-seal.mjs',line:1,category:'AUTH',severity:'high'}]},
  {verdict:'CHANGES_REQUESTED',findings:[{path:'../../private.key',line:1,category:'AUTH',severity:'high'}]},
  {verdict:'CHANGES_REQUESTED',findings:[{path:'src/checkpoint-seal.mjs',line:89,category:'AUTH',severity:'high'}]},
 ]) assert.throws(()=>parseAdvisoryPacket(pkt(o),paths),/AI09_ADVISORY_/u);
});
