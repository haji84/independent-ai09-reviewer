#!/usr/bin/env node
// Read-only review probe. Provider selected by environment; no automatic spending.
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,join} from 'node:path';
import {generateReview} from './review-providers.mjs';
const SUBJECT='haji84/PERSONAL-AI-HQ';
const SHA='3b1752a3be149c4d6402286b5d8abb807ddb05ca';
const PATH='scripts/secret-guard.mjs';
const root=resolve(process.argv[2]||'');
if(!process.argv[2]) throw Error('Provide a local checkout of PERSONAL-AI-HQ at the exact SHA');
const {execFileSync}=await import('node:child_process');
const actual=execFileSync('git',['-C',root,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
if(actual!==SHA) throw Error('Subject SHA mismatch; review refused');
const source=readFileSync(join(root,PATH),'utf8');
const sha256=createHash('sha256').update(source).digest('hex');
const prompt='Independently review the following PUBLIC source code for bypasses, secret leakage, git index/worktree mismatch, and error handling. Return concrete findings with line numbers and reproduction steps using synthetic credentials only. Never invent evidence.\\nFile: '+PATH+'\\n'+source;
const result=await generateReview(prompt);
const record={schema:'hq-independent-review-probe-v2',subject:SUBJECT,subjectSha:SHA,path:PATH,contentSha256:sha256,provider:result.provider,modelRequested:result.requestedModel,modelReturned:result.returnedModel,createdAt:new Date().toISOString(),modelResponse:result.output,usage:result.usage,independenceVerified:false,verdict:'UNVERIFIED_ADVISORY'};
mkdirSync(resolve('private-review-evidence'),{recursive:true});
const file=resolve('private-review-evidence','pr9-one-file-review.json');
writeFileSync(file,JSON.stringify(record,null,2),{mode:0o600,flag:'wx'});
console.log('Review response saved locally (not GitHub). SHA '+SHA+' file hash '+sha256+'; model '+(result.returnedModel||result.requestedModel));
console.log('Independent identity and finding reproduction must be verified separately. No approval granted.');
