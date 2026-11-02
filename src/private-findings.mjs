// Private AES-256-GCM evidence. Never log or upload plaintext model findings.
import {createHash,createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {parseSafePublicReview} from './review-schema.mjs';
const H=v=>createHash('sha256').update(v).digest('hex');
const fail=c=>{throw Error(c)};
const sha40=/^[a-f0-9]{40}$/u,sha256=/^[a-f0-9]{64}$/u;
const scopeKeys=['baseSha','end','headSha','manifestSha256','modelDigest','path',
 'promptSha256','responseSha256','reviewerSha','side','sliceId','sourceSha256','start'];
const envKeys=['ciphertext','nonce','scope','tag','version'];
const same=(v,k)=>v&&typeof v==='object'&&!Array.isArray(v)&&
 Object.keys(v).sort().join(',')===k.join(',');
function scopeCheck(s){
 if(!same(s,scopeKeys)||!sha40.test(s.baseSha)||!sha40.test(s.headSha)||
   !sha40.test(s.reviewerSha)||!sha256.test(s.manifestSha256)||
   !sha256.test(s.modelDigest)||!sha256.test(s.sourceSha256)||
   !sha256.test(s.promptSha256)||!sha256.test(s.responseSha256)||
   typeof s.path!=='string'||s.path.length<1||s.path.length>250||
   s.path.startsWith('/')||s.path.includes('..')||s.path.includes('\\')||
   !['before','after'].includes(s.side)||!Number.isSafeInteger(s.sliceId)||
   s.sliceId<1||!Number.isSafeInteger(s.start)||s.start<0||
   !Number.isSafeInteger(s.end)||s.end<=s.start)fail('AI09_PRIVATE_SCOPE_INVALID');
}
function secretKey(key){
 if(!Buffer.isBuffer(key)||key.length!==32)fail('AI09_PRIVATE_KEY_INVALID');
 return createHash('sha256').update('AI09-PRIVATE-FINDINGS-V1\0').update(key).digest();
}
function decoding(s,length){
 if(typeof s!=='string'||!/^[A-Za-z0-9_-]+$/u.test(s))fail('AI09_PRIVATE_FORMAT_INVALID');
 const b=Buffer.from(s,'base64url');
 if((length!==null&&b.length!==length)||b.toString('base64url')!==s)
   fail('AI09_PRIVATE_FORMAT_INVALID');
 return b;
}
function detailsCheck(d){
 if(!same(d,['findings','verdict'])||!Array.isArray(d.findings)||
  !['NO_FINDINGS','CHANGES_REQUESTED','INCONCLUSIVE'].includes(d.verdict)||
  (d.verdict==='NO_FINDINGS'&&d.findings.length!==0)||
  (d.verdict==='INCONCLUSIVE'&&d.findings.length!==0)||
  (d.verdict==='CHANGES_REQUESTED'&&d.findings.length===0)||
  d.findings.length>12||d.findings.some(f=>!same(f,['severity','summary'])||
    !['low','medium','high','critical'].includes(f.severity)||
    typeof f.summary!=='string'||!f.summary.trim()||f.summary.length>300||
    [...f.summary].some(x=>x.charCodeAt(0)<32||x.charCodeAt(0)===127)))
   fail('AI09_PRIVATE_FORMAT_INVALID');
}
/** Public output is SHA-only; authorized reviewers may decrypt concrete
 * findings with the private key supplied out-of-band. Source is SHA-pinned. */
export function sealPrivateModelFindings(packet,expectedModel,scope,key){
 scopeCheck(scope);const secret=secretKey(key);
 const pub=parseSafePublicReview(packet,expectedModel);
 const raw=packet.message.content;
 if(H(Buffer.from(raw,'utf8'))!==scope.responseSha256)
   fail('AI09_PRIVATE_RESPONSE_DIGEST_MISMATCH');
 const original=JSON.parse(raw);
 const details={verdict:pub.verdict,findings:original.findings};
 detailsCheck(details);
 if(Buffer.byteLength(JSON.stringify(details),'utf8')>8192)
   fail('AI09_PRIVATE_DETAILS_OVERSIZED');
 const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',secret,nonce);
 cipher.setAAD(Buffer.from(JSON.stringify(scope),'utf8'));
 const ciphertext=Buffer.concat([cipher.update(JSON.stringify(details),'utf8'),cipher.final()]);
 return {version:1,scope,nonce:nonce.toString('base64url'),
   ciphertext:ciphertext.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')};
}
export function openPrivateModelFindings(envelope,expectedScope,key){
 scopeCheck(expectedScope);const secret=secretKey(key);
 if(!same(envelope,envKeys)||envelope.version!==1||
    !same(envelope.scope,scopeKeys)||
    JSON.stringify(envelope.scope)!==JSON.stringify(expectedScope))
   fail('AI09_PRIVATE_SCOPE_OR_FORMAT_INVALID');
 const nonce=decoding(envelope.nonce,12),tag=decoding(envelope.tag,16);
 const ciphertext=decoding(envelope.ciphertext,null);
 if(ciphertext.length>8192)fail('AI09_PRIVATE_DETAILS_OVERSIZED');
 let text;
 try{
   const d=createDecipheriv('aes-256-gcm',secret,nonce);
   d.setAAD(Buffer.from(JSON.stringify(expectedScope),'utf8'));
   d.setAuthTag(tag);
   text=Buffer.concat([d.update(ciphertext),d.final()]).toString('utf8');
 }catch{fail('AI09_PRIVATE_AUTH_FAILED')}
 let details;
 try{details=JSON.parse(text)}catch{fail('AI09_PRIVATE_FORMAT_INVALID')}
 detailsCheck(details);
 return details;
}
