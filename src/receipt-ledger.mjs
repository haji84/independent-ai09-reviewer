import {openSync,writeFileSync,fsyncSync,closeSync,readFileSync,readdirSync,lstatSync} from 'node:fs';
import {join,isAbsolute} from 'node:path';
import {auditReviewReceipts} from './receipt-coverage.mjs';

const fail = code => { throw new Error(code); };
const SHARD=/^shard-([1-9][0-9]{0,3})\.json$/u;
const receiptKeys=['baseSha','evaluatedSliceIds','evidenceSha256','headSha','manifestSha256','reviewerId','shardDigest','shardId','sliceResults','status'];
const resultKeys=['findingCount','requestSha256','responseSha256','reviewSha256','sliceId','status'];
const sameKeys=(x, expected)=>x && typeof x==='object' && !Array.isArray(x) &&
  Object.keys(x).sort().join(',')===expected.join(',');
function location(directory){
  if (typeof directory!=='string' || !isAbsolute(directory) || !lstatSync(directory).isDirectory() ||
      lstatSync(directory).isSymbolicLink()) fail('AI09_LEDGER_DIRECTORY_UNSAFE');
  return directory;
}
function safeRecord(receipt){
  if (!sameKeys(receipt,receiptKeys) || !Array.isArray(receipt.sliceResults) ||
      !receipt.sliceResults.every(r=>sameKeys(r,resultKeys)))
    fail('AI09_LEDGER_SENSITIVE_OR_UNEXPECTED_FIELDS');
}
/** Atomic creation with O_EXCL: a crash/collision cannot silently replace a receipt.
 * Incomplete files fail closed on recovery. Store only hashes and bounded counts.
 * Caller must provision a private local directory, never a public workspace.
 */
export function writeReviewReceipt(directory,manifest,receipt){
  const root=location(directory);safeRecord(receipt);
  const inspected=auditReviewReceipts(manifest,[receipt],{expectedBaseSha:manifest.baseSha,expectedHeadSha:manifest.headSha});
  if(inspected.status==='BLOCKED')fail(inspected.reason);
  const id=receipt.shardId;
  const path=join(root,'shard-'+id+'.json');
  const content=JSON.stringify(receipt)+'\n';
  if(Buffer.byteLength(content,'utf8')>128*1024)fail('AI09_LEDGER_RECEIPT_TOO_LARGE');
  let fd;
  try {
    fd=openSync(path,'wx',0o600);
    writeFileSync(fd,content,'utf8');fsyncSync(fd);
  } finally {if(fd!==undefined)closeSync(fd);}
  return {shardId:id,stored:true,githubApprovalSatisfied:false,mergeAuthorized:false};
}
/** Read all saved receipts, with fixed paths and no symlink traversal. */
export function readReviewLedger(directory,manifest){
  const root=location(directory);
  const receipts=[];
  const filenames=readdirSync(root).sort();
  if(filenames.length>500)fail('AI09_LEDGER_FILE_LIMIT');
  for(const name of filenames){
    const match=SHARD.exec(name);
    if(!match)fail('AI09_LEDGER_UNEXPECTED_FILE');
    const path=join(root,name),stat=lstatSync(path);
    if(!stat.isFile() || stat.isSymbolicLink() || stat.size>128*1024 || stat.size<2)
      fail('AI09_LEDGER_FILE_UNSAFE');
    let r;try{r=JSON.parse(readFileSync(path,'utf8'));}
    catch{fail('AI09_LEDGER_JSON_INVALID');}
    safeRecord(r);
    if(String(r.shardId)!==match[1])fail('AI09_LEDGER_SHARD_NAME_MISMATCH');
    receipts.push(r);
  }
  return auditReviewReceipts(manifest,receipts,{expectedBaseSha:manifest.baseSha,expectedHeadSha:manifest.headSha});
}
