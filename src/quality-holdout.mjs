// Public out-of-sample synthetic cases, different from the eight prior smoke cases.
// Labels live in the repo and are NOT a private blind holdout. Never expose labels to the model prompt.
import {createHash} from 'node:crypto';
const H=v=>createHash('sha256').update(v).digest('hex');
const fail=c=>{throw Error(c)};
const number=lines=>lines.map((s,i)=>(i+1)+': '+s).join('\n');
const F={
 AUTH:'Assume the server provides an authenticated, non-forgeable session. This is the sole remote input gate: require both session.active and exact session.ownerId/device.ownerId equality. Ignore unrelated checks.',
 SECRET:'config.apiToken and request.headers.authorization contain secrets. Determine only whether their actual values enter logs. Literal event labels are harmless.',
 APPROVAL:'Reviews are authenticated GitHub responses. Require an APPROVED review from a distinct human on the exact headSha. Do not assume additional checks elsewhere.',
 CHECKPOINT:'trustedLatest.sha256 is the externally CAS-protected digest of the latest encrypted envelope. Restore must compare sha256(envelope) against that digest before decrypting. Source commit equality alone is insufficient.'
};
const pair=(id,family,bad,good)=>({id,family,bad:number(bad),good:number(good)});
export function outOfSampleControls(){
 const pairs=[
  pair('AUTH_OWNER','AUTH',
   ['function send(session,device,payload) {','  if(!session || !session.active) throw Error("DENIED");','  return device.applyInput(payload);','}'],
   ['function send(session,device,payload) {','  if(!session || !session.active || session.ownerId!==device.ownerId) throw Error("DENIED");','  return device.applyInput(payload);','}']),
  pair('AUTH_ACTIVE','AUTH',
   ['function relay(session,device,payload) {','  if(!session || session.ownerId!==device.ownerId) throw Error("DENIED");','  return device.dispatch(payload);','}'],
   ['function relay(session,device,payload) {','  if(!session || !session.active || session.ownerId!==device.ownerId) throw Error("DENIED");','  return device.dispatch(payload);','}']),
  pair('SECRET_DEBUG','SECRET',
   ['function connect(config,logger) {','  logger.debug({credential:config.apiToken});','  return true;','}'],
   ['function connect(config,logger) {','  logger.debug({event:"connection-ready"});','  return true;','}']),
  pair('SECRET_HEADER','SECRET',
   ['function reject(request,logger) {','  logger.info(request.headers.authorization);','  return false;','}'],
   ['function reject(request,logger) {','  logger.info("access-denied");','  return false;','}']),
  pair('APPROVAL_AUTHOR','APPROVAL',
   ['function canMerge(reviews,author,headSha) {','  return reviews.some(r=>r.state==="APPROVED" && r.commit_id===headSha);','}'],
   ['function canMerge(reviews,author,headSha) {','  return reviews.some(r=>r.state==="APPROVED" && r.commit_id===headSha &&','    r.user.type==="User" && r.user.login!==author);','}']),
  pair('APPROVAL_STALE','APPROVAL',
   ['function hasReview(reviews,author,headSha) {','  return reviews.some(r=>r.state==="APPROVED" && r.user.type==="User" &&','    r.user.login!==author);','}'],
   ['function hasReview(reviews,author,headSha) {','  return reviews.some(r=>r.state==="APPROVED" && r.user.type==="User" &&','    r.user.login!==author && r.commit_id===headSha);','}']),
  pair('CHECKPOINT_SCOPE','CHECKPOINT',
   ['function restore(envelope,trustedLatest) {','  if(envelope.headSha!==trustedLatest.headSha) throw Error("MOVED");','  return decrypt(envelope);','}'],
   ['function restore(envelope,trustedLatest) {','  if(sha256(envelope)!==trustedLatest.sha256) throw Error("STALE");','  return decrypt(envelope);','}']),
  pair('CHECKPOINT_PREVIOUS','CHECKPOINT',
   ['function resume(envelope,trustedLatest) {','  if(sha256(envelope)!==trustedLatest.previousSha256) throw Error("STALE");','  return decrypt(envelope);','}'],
   ['function resume(envelope,trustedLatest) {','  if(sha256(envelope)!==trustedLatest.sha256) throw Error("STALE");','  return decrypt(envelope);','}'])
 ];
 return pairs.flatMap(p=>[
   {id:'H_'+p.id+'_U',family:p.family,kind:'synthetic-unsafe',
    focus:F[p.family],code:p.bad,maxLine:p.bad.split('\n').length,
    expected:'CHANGES_REQUESTED',expectedCategory:p.family},
   {id:'H_'+p.id+'_S',family:p.family,kind:'synthetic-defensive',
    focus:F[p.family],code:p.good,maxLine:p.good.split('\n').length,
    expected:'NO_FINDINGS'}
 ]);
}
export function auditOutOfSample(smoke,held=outOfSampleControls()){
 if(!Array.isArray(smoke)||!Array.isArray(held)||held.length!==16)
   fail('AI09_HOLDOUT_COUNT_INVALID');
 const ids=new Set(smoke.map(x=>x.id));
 const codeHashes=new Set(smoke.map(x=>H(x.code??'')));
 const tally={AUTH:[0,0],SECRET:[0,0],APPROVAL:[0,0],CHECKPOINT:[0,0]};
 for(const c of held){
   if(!c||typeof c.id!=='string'||!c.id.startsWith('H_')||
      ids.has(c.id)||!Object.hasOwn(tally,c.family)||
      typeof c.focus!=='string'||c.focus.length<60||
      typeof c.code!=='string'||c.maxLine!==c.code.split('\n').length||
      c.code.split('\n').some((s,i)=>!s.startsWith((i+1)+': '))||
      c.maxLine<3||c.maxLine>8||
      (c.expected!=='CHANGES_REQUESTED'&&c.expected!=='NO_FINDINGS')||
      (c.expected==='CHANGES_REQUESTED'&&c.expectedCategory!==c.family)||
      (c.expected==='NO_FINDINGS'&&c.expectedCategory!==undefined))
      fail('AI09_HOLDOUT_FIXTURE_INVALID');
   const h=H(c.code);
   if(codeHashes.has(h))fail('AI09_HOLDOUT_CODE_COLLISION');
   ids.add(c.id);codeHashes.add(h);
   tally[c.family][c.expected==='CHANGES_REQUESTED'?0:1]++;
 }
 if(Object.values(tally).some(([bad,good])=>bad!==2||good!==2))
   fail('AI09_HOLDOUT_UNBALANCED');
 return {count:held.length,unsafe:8,safe:8,
   datasetSha256:H(JSON.stringify(held)),
   classification:'PUBLIC_OUT_OF_SAMPLE_NOT_PRIVATE_BLIND'};
}
