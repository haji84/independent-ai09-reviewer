import test from 'node:test';
import assert from 'node:assert/strict';
import {assessIndependentApproval} from '../src/verify-independent-approval.mjs';
const head='a'.repeat(40),mainSha='b'.repeat(40);
const pr=()=>({number:1,state:'closed',merged:true,merged_at:'2026-11-02T01:00:00Z',
 merge_commit_sha:mainSha,user:{login:'haji84'},
 head:{sha:head,repo:{full_name:'haji84/independent-ai09-reviewer'}},
 base:{ref:'main'}});
const review=(login='reviewer-other',state='APPROVED',sha=head,type='User')=>({
 user:{login,type},state,commit_id:sha,submitted_at:'2026-11-02T00:59:00Z'});
test('real separate GitHub user approves reviewed candidate on the exact main merge',()=>{
 const x=assessIndependentApproval(pr(),[review()],{mainSha});
 assert.equal(x.independentApprovalChecked,true);
 assert.equal(x.reviewerCount,1);
});
test('owner, bot, old revision, comment-only, and no review fail closed',()=>{
 for(const rs of [
  [review('haji84')],[review('coderabbitai[bot]','APPROVED',head,'Bot')],
  [review('reviewer-other','APPROVED','c'.repeat(40))],
  [review('reviewer-other','COMMENTED')],[]
 ])assert.throws(()=>assessIndependentApproval(pr(),rs,{mainSha}),
   /AI09_(NO_DISTINCT_CURRENT_APPROVED_REVIEW|INDEPENDENT_REVIEW_SCOPE_INVALID)/u);
});
test('newer change request and unmerged or unrelated main revision fail closed',()=>{
 const earlier=review();
 const later={...review('reviewer-other','CHANGES_REQUESTED'),submitted_at:'2026-11-02T01:01:00Z'};
 assert.throws(()=>assessIndependentApproval(pr(),[earlier,later],{mainSha}),
   /UNRESOLVED_CHANGE_REQUEST/u);
 assert.throws(()=>assessIndependentApproval(pr(),[earlier],{mainSha:'d'.repeat(40)}),
   /INDEPENDENT_REVIEW_SCOPE_INVALID/u);
 assert.throws(()=>assessIndependentApproval({...pr(),merged:false},[earlier],{mainSha}),
   /INDEPENDENT_REVIEW_SCOPE_INVALID/u);
});
