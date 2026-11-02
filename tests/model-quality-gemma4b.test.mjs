import test from 'node:test';
import assert from 'node:assert/strict';
import {parseQualityPacket,selectLineWindow} from '../src/model-quality-gemma4b.mjs';
const pkt=o=>({model:'gemma3:4b',done:true,done_reason:'stop',
 message:{content:JSON.stringify(o)}});
test('known-bad and defensive verdicts retain bounded code locations',()=>{
 assert.deepEqual(parseQualityPacket(pkt({verdict:'CHANGES_REQUESTED',category:'AUTH',line:2}),3),
  {verdict:'CHANGES_REQUESTED',category:'AUTH',line:2});
 assert.deepEqual(parseQualityPacket(pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),4),
  {verdict:'NO_FINDINGS',category:'NONE',line:0});
});
test('contradictory, forged or out-of-window results are blocked',()=>{
 assert.equal(parseQualityPacket(pkt({verdict:'INCONCLUSIVE',category:'NONE',line:0}),5).verdict,'INCONCLUSIVE');
 for(const x of [
  {verdict:'CHANGES_REQUESTED',category:'NONE',line:2},
  {verdict:'NO_FINDINGS',category:'AUTH',line:2},
  {verdict:'INCONCLUSIVE',category:'AUTH',line:1},
  {verdict:'CHANGES_REQUESTED',category:'AUTH',line:6},
  {verdict:'CHANGES_REQUESTED',category:'AUTH',line:-1},
  {verdict:'NO_FINDINGS',category:'NONE',line:1},
  {verdict:'CHANGES_REQUESTED',category:'AUTH',line:2,token:'secret'},
 ])assert.throws(()=>parseQualityPacket(pkt(x),5),/AI09_4B_SCHEMA_INVALID/u);
});
test('wrong model, incomplete and non-JSON responses fail',()=>{
 for(const x of [
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),done:false},
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),model:'gemma3:1b'},
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),done_reason:'length'},
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),message:{content:'not-json'}}
 ])assert.throws(()=>parseQualityPacket(x,3),/AI09_4B_/u);
});
test('line windows are bounded, literal and preserve source numbering',()=>{
 assert.deepEqual(selectLineWindow('a\nb\nc\nd\n',2,3),
  {snippet:'2: b\n3: c',start:2,end:3,bytes:9});
 assert.throws(()=>selectLineWindow('a\nb',2,5),/WINDOW_INVALID/u);
 assert.throws(()=>selectLineWindow('x\n'.repeat(500),1,500,80),/SOURCE_TOO_LARGE/u);
});
