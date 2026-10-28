#!/usr/bin/env node
// Local-only, read-only review probe. Requires running Ollama and a previously installed model.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,join} from 'node:path';
const SUBJECT='haji84/PERSONAL-AI-HQ';
const SHA='3b1752a3be149c4d6402286b5d8abb807ddb05ca';
const PATH='scripts/secret-guard.mjs';
const model=process.env.REVIEW_MODEL;
if(!model || !/^[a-zA-Z0-9_.:\/-]{1,120}$/.test(model)) throw Error('REVIEW_MODEL must name a locally installed independent model');
const root=resolve(process.argv[2]||'');
if(!process.argv[2]) throw Error('Provide a local checkout of PERSONAL-AI-HQ at the exact SHA');
const {execFileSync}=await import('node:child_process');
const actual=execFileSync('git',['-C',root,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
if(actual!==SHA) throw Error('Subject SHA mismatch; review refused');
const source=readFileSync(join(root,PATH),'utf8');
const sha256=createHash('sha256').update(source).digest('hex');
const prompt='Independently review the following PUBLIC source code for bypasses, secret leakage, git index/worktree mismatch, and error handling. Return concrete findings with line numbers and reproduction steps using synthetic credentials only. Never invent evidence.\\nFile: '+PATH+'\\n'+source;
const endpoint=process.env.OLLAMA_URL||'http://127.0.0.1:11434';
const u=new URL(endpoint);
if(!['127.0.0.1','localhost','::1','[::1]'].includes(u.hostname)) throw Error('Only loopback Ollama endpoint is permitted');
const ctrl=new AbortController();
const timer=setTimeout(()=>ctrl.abort(),120000);
let response;
try {
 response=await fetch(new URL('/api/generate',u),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({model,prompt,stream:false,options:{temperature:0}}),signal:ctrl.signal});
}finally{clearTimeout(timer)}
if(!response.ok) throw Error('Model request failed: HTTP '+response.status);
const data=await response.json();
if(typeof data.response!=='string'||!data.response.trim()||data.done!==true) throw Error('No completed real model response');
const record={schema:'hq-independent-review-probe-v1',subject:SUBJECT,subjectSha:SHA,path:PATH,contentSha256:sha256,modelRequested:model,modelReturned:data.model||null,createdAt:new Date().toISOString(),modelDone:data.done,modelResponse:data.response,evalCount:data.eval_count??null,independenceVerified:false,verdict:'UNVERIFIED_ADVISORY'};
mkdirSync(resolve('private-review-evidence'),{recursive:true});
const file=resolve('private-review-evidence','pr9-one-file-review.json');
writeFileSync(file,JSON.stringify(record,null,2),{mode:0o600,flag:'wx'});
console.log('Review response saved locally (not GitHub). SHA '+SHA+' file hash '+sha256+'; model '+(data.model||model));
console.log('Independent identity and finding reproduction must be verified separately. No approval granted.');
