// Encrypted portable progress checkpoint. Offline candidate only: no Actions activation.
// The key is caller-supplied, must never be included in artifacts or repository files.
import {createCipheriv,createDecipheriv,createHash,randomBytes} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {auditReviewReceipts} from './receipt-coverage.mjs';
import {assertSafeReceiptFields} from './receipt-ledger.mjs';

const sha40=/^[a-f0-9]{40}$/u,sha256=/^[a-f0-9]{64}$/u;
const fail=code=>{throw new Error(code)};
const exactKeys=(obj,keys)=>obj && typeof obj==='object' && !Array.isArray(obj) &&
  Object.keys(obj).sort().join(',')===keys.slice().sort().join(',');
const MAX_PLAINTEXT=1024*1024;
function keyBuffer(key){
  if(!Buffer.isBuffer(key)||key.length!==32)fail('AI09_CHECKPOINT_KEY_INVALID');
  return key;
}
function identity(manifest,reviewerSha){
  if(!sha40.test(reviewerSha??'')||!sha40.test(manifest?.baseSha??'')||
    !sha40.test(manifest?.headSha??'')||!sha256.test(manifest?.manifestSha256??''))
    fail('AI09_CHECKPOINT_IDENTITY_INVALID');
  return {baseSha:manifest.baseSha,headSha:manifest.headSha,
    manifestSha256:manifest.manifestSha256,reviewerSha};
}
function validated(manifest,receipts){
  if(!Array.isArray(receipts)||receipts.length>500)
    fail('AI09_CHECKPOINT_RECEIPTS_INVALID');
  for(const receipt of receipts)assertSafeReceiptFields(receipt);
  const state=auditReviewReceipts(manifest,receipts,
    {expectedBaseSha:manifest.baseSha,expectedHeadSha:manifest.headSha});
  if(state.status==='BLOCKED')fail('AI09_CHECKPOINT_RECEIPTS_INVALID');
  return state;
}
function authenticatedData(scope){return Buffer.from(JSON.stringify(scope),'utf8')}
// Caller must obtain this digest from CAS-protected durable state. The
// ciphertext's own authenticated fields cannot prove it is the LATEST.
export function checkpointEnvelopeSha256(envelope){
  if(!exactKeys(envelope,['version','scope','nonce','ciphertext','tag']))
    fail('AI09_CHECKPOINT_SCOPE_OR_FORMAT_INVALID');
  return createHash('sha256').update(JSON.stringify(envelope)).digest('hex');
}

/** Seal SHA-only records under an externally provisioned 256-bit secret.
 * Artifacts may contain only the returned envelope, not the key, prompts, or sources.
 * This does not authenticate the external model or constitute GitHub approval.
 */
export function sealReviewCheckpoint(manifest,receipts,reviewerSha,key){
  const scope=identity(manifest,reviewerSha),secret=keyBuffer(key);
  validated(manifest,receipts);
  const clear=Buffer.from(JSON.stringify({version:1,receipts}),'utf8');
  if(clear.length>MAX_PLAINTEXT)fail('AI09_CHECKPOINT_SIZE_LIMIT');
  const nonce=randomBytes(12);
  const cipher=createCipheriv('aes-256-gcm',secret,nonce);
  cipher.setAAD(authenticatedData(scope));
  const ciphertext=Buffer.concat([cipher.update(clear),cipher.final()]);
  return {version:1,scope,nonce:nonce.toString('base64url'),
    ciphertext:ciphertext.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')};
}

/** Fail closed unless an independent durable trusted-latest digest matches.
 * External atomic generation tracking and CAS remain a release prerequisite. */
export function openReviewCheckpoint(envelope,manifest,reviewerSha,key,
  {trustedLatestCheckpointSha256}={}){
  if(!sha256.test(trustedLatestCheckpointSha256??''))
    fail('AI09_CHECKPOINT_TRUSTED_LATEST_REQUIRED');
  if(checkpointEnvelopeSha256(envelope)!==trustedLatestCheckpointSha256)
    fail('AI09_CHECKPOINT_ROLLBACK_OR_SWAP');
  const scope=identity(manifest,reviewerSha),secret=keyBuffer(key);
  if(!exactKeys(envelope,['version','scope','nonce','ciphertext','tag'])||
    envelope.version!==1||!exactKeys(envelope.scope,
      ['baseSha','headSha','manifestSha256','reviewerSha'])||
    JSON.stringify(envelope.scope)!==JSON.stringify(scope)||
    typeof envelope.nonce!=='string'||typeof envelope.tag!=='string'||
    typeof envelope.ciphertext!=='string'||
    !/^[A-Za-z0-9_-]+$/u.test(envelope.ciphertext)||
    envelope.ciphertext.length>2*MAX_PLAINTEXT||
    !/^[A-Za-z0-9_-]{16}$/u.test(envelope.nonce)||
    !/^[A-Za-z0-9_-]{22}$/u.test(envelope.tag))
    fail('AI09_CHECKPOINT_SCOPE_OR_FORMAT_INVALID');
  const nonce=Buffer.from(envelope.nonce,'base64url');
  const tag=Buffer.from(envelope.tag,'base64url');
  const enc=Buffer.from(envelope.ciphertext,'base64url');
  if(nonce.length!==12||tag.length!==16||enc.length>MAX_PLAINTEXT||
    nonce.toString('base64url')!==envelope.nonce||
    tag.toString('base64url')!==envelope.tag||
    enc.toString('base64url')!==envelope.ciphertext)
    fail('AI09_CHECKPOINT_SCOPE_OR_FORMAT_INVALID');
  let plain;
  try{
    const decipher=createDecipheriv('aes-256-gcm',secret,nonce);
    decipher.setAAD(authenticatedData(scope));
    decipher.setAuthTag(tag);
    plain=Buffer.concat([decipher.update(enc),decipher.final()]);
  }catch{fail('AI09_CHECKPOINT_AUTH_FAILED')}
  if(plain.length>MAX_PLAINTEXT)fail('AI09_CHECKPOINT_SIZE_LIMIT');
  let data;
  try{data=JSON.parse(plain.toString('utf8'))}
  catch{fail('AI09_CHECKPOINT_FORMAT_INVALID')}
  if(!exactKeys(data,['version','receipts'])||data.version!==1)
    fail('AI09_CHECKPOINT_FORMAT_INVALID');
  return {receipts:data.receipts,state:validated(manifest,data.receipts)};
}
