// Candidate read-only public GitHub review gate for model workflow activation.
// Caller-supplied matching SHAs are not proof of an independent approval.
import {pathToFileURL} from 'node:url';
const fail=c=>{throw Error(c)};
const SHA=/^[a-f0-9]{40}$/u;
const REPO='haji84/independent-ai09-reviewer';
export function assessIndependentApproval(pr,reviews,{mainSha}={}){
 if(!pr||pr.number!==1||pr.state!=='closed'||pr.merged!==true||
    typeof pr.merged_at!=='string'||!SHA.test(mainSha??'')||
    pr.merge_commit_sha!==mainSha||pr.base?.ref!=='main'||
    pr.head?.repo?.full_name!==REPO||!SHA.test(pr.head?.sha??'')||
    pr.user?.login!=='haji84'||!Array.isArray(reviews)||
    reviews.length===0||reviews.length>=100)
   fail('AI09_INDEPENDENT_REVIEW_SCOPE_INVALID');
 const byReviewer=new Map();
 for(const r of reviews){
   const login=r?.user?.login;
   if(typeof login!=='string'||!login||typeof r.state!=='string'||
      typeof r.submitted_at!=='string')fail('AI09_REVIEW_RECORD_INVALID');
   if(!['COMMENTED','APPROVED','CHANGES_REQUESTED','DISMISSED'].includes(r.state))
      continue;
   if(r.state==='COMMENTED')continue;
   const previous=byReviewer.get(login);
   if(!previous||r.submitted_at>=previous.submitted_at)byReviewer.set(login,r);
 }
 if([...byReviewer.values()].some(r=>r.state==='CHANGES_REQUESTED'))
   fail('AI09_UNRESOLVED_CHANGE_REQUEST');
 const valid=[...byReviewer.values()].filter(r=>r.state==='APPROVED'&&
   r.user?.login!=='haji84'&&r.user?.type==='User'&&r.commit_id===pr.head.sha);
 if(!valid.length)fail('AI09_NO_DISTINCT_CURRENT_APPROVED_REVIEW');
 return {reviewerHead:pr.head.sha,mainSha,independentApprovalChecked:true,
   reviewerCount:valid.length};
}
async function get(url){
 const r=await fetch(url,{headers:{accept:'application/vnd.github+json',
   'user-agent':'ai09-approved-review-gate'},signal:AbortSignal.timeout(15000)});
 if(!r.ok)fail('AI09_APPROVAL_API_UNAVAILABLE');
 return await r.json();
}
async function main(){
 const mainSha=process.env.GITHUB_SHA;
 if(process.env.GITHUB_REPOSITORY!==REPO||
    process.env.GITHUB_REF!=='refs/heads/main'||!SHA.test(mainSha??''))
   fail('AI09_APPROVAL_RUNNER_SCOPE_INVALID');
 const root='https://api.github.com/repos/'+REPO+'/pulls/1';
 const pr=await get(root),reviews=await get(root+'/reviews?per_page=100');
 const proof=assessIndependentApproval(pr,reviews,{mainSha});
 console.log('AI09_INDEPENDENT_GITHUB_REVIEW=VERIFIED');
 console.log('AI09_APPROVED_REVIEWER_HEAD='+proof.reviewerHead);
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(e=>{
   console.error(/^AI09_[A-Z0-9_]+$/u.test(e?.message??'')?e.message:'AI09_APPROVAL_CHECK_ERROR');
   process.exitCode=1;
 });
}
