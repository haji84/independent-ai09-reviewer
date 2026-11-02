import {createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';
const refuse=reason=>{throw Error(reason);};
const hash=text=>createHash('sha256').update(text).digest('hex');
// Pure, fail-closed parser. Public evidence never contains raw model findings.
export function parseSafePublicReview(packet,expectedModel) {
  if(!packet||packet.model!==expectedModel||packet.done!==true||
    packet.done_reason!=='stop'||typeof packet.message?.content!=='string'||
    Buffer.byteLength(packet.message.content,'utf8')>16000)
    refuse('AI09_RESPONSE_INVALID');
  let obj;try{obj=JSON.parse(packet.message.content);}
  catch{refuse('AI09_RESPONSE_NON_JSON');}
  if(!obj||typeof obj!=='object'||Array.isArray(obj)||
    Object.keys(obj).sort().join(',')!=='findings,verdict'||
    !['NO_FINDINGS','CHANGES_REQUESTED','INCONCLUSIVE'].includes(obj.verdict)||
    !Array.isArray(obj.findings)||obj.findings.length>12||
    (obj.verdict==='NO_FINDINGS'&&obj.findings.length!==0)||
    (obj.verdict==='CHANGES_REQUESTED'&&obj.findings.length===0)||
    (obj.verdict==='INCONCLUSIVE'&&obj.findings.length!==0))
    refuse('AI09_RESPONSE_SCHEMA_INVALID');
  const findings=[];
  for(const f of obj.findings){
    if(!f||typeof f!=='object'||Array.isArray(f)||
      Object.keys(f).sort().join(',')!=='severity,summary'||
      !['low','medium','high','critical'].includes(f.severity)||
      typeof f.summary!=='string'||!f.summary.trim()||
      f.summary.length>300||
      [...f.summary].some(c=>c.charCodeAt(0)<32||c.charCodeAt(0)===127))
      refuse('AI09_RESPONSE_SCHEMA_INVALID');
    findings.push({severity:f.severity,summarySha256:hash(Buffer.from(f.summary,'utf8'))});
  }
  return {verdict:obj.verdict,findings};
}

// A partial canary is never a full review or a GitHub approval.
// Surface detected findings even when other slices are unknown or unreviewed.
export function summarizePartialModelReview(records,totalSlices,{stale=false}={}) {
  if(!Array.isArray(records)||!Number.isSafeInteger(totalSlices)||totalSlices<1||
    records.length>totalSlices||typeof stale!=='boolean')
    refuse('AI09_PARTIAL_RECORD_INVALID');
  const ids=new Set();
  let changesRequestedSlices=0,inconclusiveSlices=0,findingCount=0;
  for(const record of records){
    if(!record||!Number.isSafeInteger(record.id)||record.id<1||
      record.id>totalSlices||ids.has(record.id)||
      !['NO_FINDINGS','CHANGES_REQUESTED','INCONCLUSIVE'].includes(record.verdict)||
      !Array.isArray(record.findings)||
      (record.verdict==='NO_FINDINGS'&&record.findings.length!==0)||
      (record.verdict==='CHANGES_REQUESTED'&&record.findings.length===0)||
      (record.verdict==='INCONCLUSIVE'&&record.findings.length!==0)||
      record.findings.some(f=>!f||!['low','medium','high','critical'].includes(f.severity)||
        !/^[a-f0-9]{64}$/u.test(f.summarySha256??'')))
      refuse('AI09_PARTIAL_RECORD_INVALID');
    ids.add(record.id);
    if(record.verdict==='CHANGES_REQUESTED'){
      changesRequestedSlices++;
      findingCount+=record.findings.length;
    }else if(record.verdict==='INCONCLUSIVE')inconclusiveSlices++;
  }
  const verdict=changesRequestedSlices?'CHANGES_REQUESTED':
    inconclusiveSlices?'INCONCLUSIVE':'NO_FINDINGS';
  const status=stale?'HISTORICAL_PARTIAL_MODEL_REVIEW_ONLY':
    changesRequestedSlices?'PARTIAL_MODEL_REVIEW_HAS_FINDINGS':
    inconclusiveSlices?'PARTIAL_MODEL_REVIEW_INCONCLUSIVE':
    'PARTIAL_MODEL_REVIEW_PENDING';
  return {status,verdict,changesRequestedSlices,inconclusiveSlices,findingCount,
    pendingSlices:totalSlices-records.length,githubApprovalSatisfied:false,
    mergeAuthorized:false};
}
