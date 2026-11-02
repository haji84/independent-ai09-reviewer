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

test('new out-of-sample suite has 16 distinct balanced examples and no prior code repeats',async()=>{
 const {outOfSampleControls,auditOutOfSample}=await import('../src/quality-holdout.mjs');
 const cases=outOfSampleControls();
 const scope=auditOutOfSample(pairedSecurityControls(),cases);
 assert.deepEqual([scope.count,scope.unsafe,scope.safe],[16,8,8]);
 assert.match(scope.datasetSha256,/^[a-f0-9]{64}$/u);
 assert.equal(scope.classification,'PUBLIC_OUT_OF_SAMPLE_NOT_PRIVATE_BLIND');
 for(const family of ['AUTH','SECRET','APPROVAL','CHECKPOINT']){
   assert.equal(cases.filter(x=>x.family===family&&x.expected==='CHANGES_REQUESTED').length,2);
   assert.equal(cases.filter(x=>x.family===family&&x.expected==='NO_FINDINGS').length,2);
 }
});
test('out-of-sample TP/TN, FP/FN, abstain, and invalid stay separate',async()=>{
 const {outOfSampleControls}=await import('../src/quality-holdout.mjs');
 const fixtures=outOfSampleControls();
 const all=fixtures.map(x=>({id:x.id,verdict:x.expected,
  category:x.expected==='CHANGES_REQUESTED'?x.expectedCategory:'NONE',line:2}));
 const correct=scoreModelCalibration(fixtures,all);
 assert.deepEqual([correct.total,correct.positive,correct.negative],[16,8,8]);
 assert.equal(correct.passed,true);
 assert.equal(correct.modelPromotionAuthorized,false);
 const changed=all.map((r,i)=>i===0?{...r,verdict:'NO_FINDINGS',category:'NONE'}:
  i===1?{...r,verdict:'CHANGES_REQUESTED',category:'AUTH'}:
  i===2?{...r,verdict:'INCONCLUSIVE',category:'NONE'}:
  i===3?{...r,verdict:'INVALID'}:r);
 const scored=scoreModelCalibration(fixtures,changed);
 assert.equal(scored.fn,1);assert.equal(scored.fp,1);
 assert.equal(scored.abstain,1);assert.equal(scored.invalid,1);
 assert.equal(scored.passed,false);
});
test('holdout rejects old smoke code, duplicate labels, and changed balance',async()=>{
 const {outOfSampleControls,auditOutOfSample}=await import('../src/quality-holdout.mjs');
 const cases=outOfSampleControls(),smoke=pairedSecurityControls();
 assert.throws(()=>auditOutOfSample(smoke,[...cases.slice(0,-1),cases[0]]),/AI09_HOLDOUT_FIXTURE_INVALID/u);
 assert.throws(()=>auditOutOfSample(smoke,[...cases.slice(0,-1),
  {...cases[15],code:smoke[0].code,maxLine:smoke[0].maxLine}]),/AI09_HOLDOUT_CODE_COLLISION/u);
 assert.throws(()=>auditOutOfSample(smoke,[...cases.slice(0,-1),
  {...cases[15],expected:'CHANGES_REQUESTED',expectedCategory:'CHECKPOINT'}]),
  /AI09_HOLDOUT_UNBALANCED/u);
});
test('four-stage advisory never converts synthetic success to authenticated approval',async()=>{
 const {assessCompositeAdvisory}=await import('../src/model-quality-probe.mjs');
 const {outOfSampleControls}=await import('../src/quality-holdout.mjs');
 const outcome=fixtures=>fixtures.map(x=>({id:x.id,verdict:x.expected,
  category:x.expected==='CHANGES_REQUESTED'?x.expectedCategory:'NONE',line:2}));
 const summary=assessCompositeAdvisory({
  smokeRecords:outcome(pairedSecurityControls()),
  holdoutRecords:outcome(outOfSampleControls())});
 assert.equal(summary.modelSmokePassed,true);
 assert.equal(summary.outOfSamplePassed,true);
 assert.equal(summary.mechanicalStatus,'BLOCKED');
 assert.equal(summary.sourceGitBlobProvenance,'UNVERIFIED');
 assert.equal(summary.authenticatedSeparateGitHubApproval,'REQUIRED_NOT_CHECKED');
 assert.equal(summary.mergeAuthorized,false);
});
