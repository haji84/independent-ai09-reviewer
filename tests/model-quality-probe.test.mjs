import test from 'node:test';
import assert from 'node:assert/strict';
import {parseQualityPacket,selectLineWindow,pairedAuthorizationControls,pairedSecurityControls,publicPacketDiagnostics,scoreModelCalibration} from '../src/model-quality-probe.mjs';
const pkt=o=>({model:'qwen2.5-coder:14b',done:true,done_reason:'stop',
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
 ])assert.throws(()=>parseQualityPacket(pkt(x),5),/AI09_QUALITY_SCHEMA_INVALID/u);
});
test('wrong model, incomplete and non-JSON responses fail',()=>{
 for(const x of [
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),done:false},
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),model:'gemma3:1b'},
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),done_reason:'length'},
  {...pkt({verdict:'NO_FINDINGS',category:'NONE',line:0}),message:{content:'not-json'}}
 ])assert.throws(()=>parseQualityPacket(x,3),/AI09_QUALITY_/u);
});
test('line windows are bounded, literal and preserve source numbering',()=>{
 assert.deepEqual(selectLineWindow('a\nb\nc\nd\n',2,3),
  {snippet:'2: b\n3: c',start:2,end:3,bytes:9});
 assert.throws(()=>selectLineWindow('a\nb',2,5),/WINDOW_INVALID/u);
 assert.throws(()=>selectLineWindow('x\n'.repeat(500),1,500,80),/SOURCE_TOO_LARGE/u);
});

test('paired calibration shares a trusted-session threat model and opposite expected outcomes',()=>{
 const v=pairedAuthorizationControls();
 assert.equal(v.length,2);
 assert.equal(v[0].focus,v[1].focus);
 assert.ok(v[0].focus.includes('non-forgeable'));
 assert.equal(v[0].expected,'CHANGES_REQUESTED');
 assert.equal(v[1].expected,'NO_FINDINGS');
 assert.ok(!v[0].code.includes('session.active'));
 assert.ok(v[1].code.includes('session.active'));
});


test('bounded candidate benchmark has four unsafe and four safe controls with explicit expectations',()=>{
 const all=pairedSecurityControls();
 assert.equal(all.length,8);
 assert.equal(new Set(all.map(x=>x.id)).size,8);
 assert.equal(all.filter(x=>x.expected==='CHANGES_REQUESTED').length,4);
 assert.equal(all.filter(x=>x.expected==='NO_FINDINGS').length,4);
 for(const x of all){
   assert.ok(x.focus.length>50);
   assert.ok(x.code.startsWith('1: '));
   assert.ok(x.code.includes('\n'));
   assert.ok(x.maxLine>=x.code.split('\n').length);
 }
 assert.equal(all.find(x=>x.id==='CHECKPOINT_CAS_CHECK').expected,'NO_FINDINGS');
 assert.equal(all.find(x=>x.id==='SECRET_LOG_LEAK').expectedCategory,'SECRET');
 assert.equal(all.find(x=>x.id==='APPROVAL_SELF_ACCEPT').expectedCategory,'APPROVAL');
});
test('benchmark model parses strict positive and negative multi-category verdicts',()=>{
 for(const category of ['AUTH','APPROVAL','SECRET','CHECKPOINT']){
   assert.equal(parseQualityPacket(pkt({verdict:'CHANGES_REQUESTED',category,line:2}),4).category,category);
 }
 assert.throws(()=>parseQualityPacket(pkt({verdict:'INCONCLUSIVE',category:'SECRET',line:1}),4),/AI09_QUALITY_SCHEMA_INVALID/u);
});


test('diagnostic telemetry distinguishes format/semantic errors without leaking untrusted model strings',()=>{
 const safe=publicPacketDiagnostics(pkt({verdict:'CHANGES_REQUESTED',category:'AUTH',line:2}),3);
 assert.equal(safe.kind,'JSON_OBJECT');
 assert.equal(safe.exactKeys,true);
 assert.equal(safe.verdict,'CHANGES_REQUESTED');
 assert.equal(safe.validLineRange,true);
 const bad=publicPacketDiagnostics(pkt({verdict:'CHANGES_REQUESTED',
   category:'SECRET',line:7,token:'Authorization: Bearer SUPERSECRET'}),3);
 assert.equal(bad.kind,'JSON_OBJECT');
 assert.equal(bad.exactKeys,false);
 assert.equal(bad.validLineRange,false);
 assert.equal(JSON.stringify(bad).includes('SUPERSECRET'),false);
 const unknown=publicPacketDiagnostics(pkt({verdict:'NONSENSE',
   category:'UNTRUSTED-MODEL-SECRET',line:'2'}),3);
 assert.equal(unknown.verdict,'UNRECOGNIZED');
 assert.equal(unknown.category,'UNRECOGNIZED');
 assert.equal(unknown.integerLine,false);
 assert.equal(JSON.stringify(unknown).includes('UNTRUSTED-MODEL-SECRET'),false);
 assert.equal(publicPacketDiagnostics({...pkt({}),message:{content:'bad'}},3).kind,'INVALID');
});


test('metrics separate FP and FN from abstentions and malformed responses',()=>{
 const f=pairedSecurityControls();
 const r=[
  {id:f[0].id,verdict:'NO_FINDINGS'},
  {id:f[1].id,verdict:'CHANGES_REQUESTED',category:'AUTH'},
  {id:f[2].id,verdict:'INCONCLUSIVE'},
  {id:f[3].id,verdict:'INVALID'}
 ];
 const s=scoreModelCalibration(f,r);
 assert.deepEqual([s.positive,s.negative,s.fn,s.fp,s.abstain,s.invalid,s.pending],
   [4,4,1,1,1,1,4]);
 assert.equal(s.observedFPR,0.25);
 assert.equal(s.observedFNR,0.25);
 assert.equal(s.status,'BENCHMARK_PARTIAL');
 assert.equal(s.passed,false);
});
test('only all exact known-bad and known-safe verdicts pass a smoke gate',()=>{
 const f=pairedSecurityControls();
 const all=f.map(x=>({id:x.id,verdict:x.expected,
   category:x.expected==='CHANGES_REQUESTED'?x.expectedCategory:'NONE',line:2}));
 const good=scoreModelCalibration(f,all);
 assert.equal(good.passed,true);
 assert.equal(good.tp,4);
 assert.equal(good.tn,4);
 assert.equal(good.formalGitHubApproval,false);
 assert.equal(good.modelPromotionAuthorized,false);
 const wrong=all.map((x,i)=>i===2?{...x,category:'OTHER'}:x);
 assert.equal(scoreModelCalibration(f,wrong).wrongCategory,1);
 assert.equal(scoreModelCalibration(f,wrong).passed,false);
});
test('duplicate and unknown model receipts cannot count as reviewed',()=>{
 const f=pairedSecurityControls();
 assert.throws(()=>scoreModelCalibration(f,[{id:f[0].id,verdict:'INVALID'},
   {id:f[0].id,verdict:'NO_FINDINGS'}]),/AI09_BENCHMARK_RECORD_INVALID/u);
 assert.throws(()=>scoreModelCalibration(f,[{id:'not-a-fixture',verdict:'NO_FINDINGS'}]),
   /AI09_BENCHMARK_RECORD_INVALID/u);
 const unknown=f.map(x=>({id:x.id,verdict:'INVALID'}));
 const r=scoreModelCalibration(f,unknown);
 assert.equal(r.status,'CALIBRATION_FAILED');
 assert.equal(r.invalid,8);
 assert.equal(r.fp,0);assert.equal(r.fn,0);
});
