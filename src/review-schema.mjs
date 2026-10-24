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
    (obj.verdict==='CHANGES_REQUESTED'&&obj.findings.length===0))
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
