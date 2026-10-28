import test from 'node:test';
import assert from 'node:assert/strict';
import {geminiConfig,geminiReview} from '../scripts/gemini-provider.mjs';
const env={GEMINI_API_KEY:'synthetic-not-a-real-key',REVIEW_MODEL:'gemini-2.5-flash',REVIEW_ALLOW_PAID:'false'};
test('missing key and paid-flag ambiguity fail closed',()=>{
 assert.throws(()=>geminiConfig({...env,GEMINI_API_KEY:''}));
 assert.throws(()=>geminiConfig({...env,REVIEW_ALLOW_PAID:'true'}));
});
test('mock response preserves model identity and never prints credentials',async()=>{
 let captured;
 const fake=async(url,options)=>{captured={url:url.toString(),headers:options.headers,body:options.body};return {ok:true,json:async()=>({modelVersion:'gemini-2.5-flash',candidates:[{content:{parts:[{text:'synthetic review result'}]}}],usageMetadata:{totalTokenCount:20}})}};
 const result=await geminiReview('synthetic public code',env,fake);
 assert.equal(result.output,'synthetic review result');
 assert.equal(result.returnedModel,'gemini-2.5-flash');
 assert.equal(new URL(captured.url).hostname,'generativelanguage.googleapis.com');
 assert.ok(!captured.url.includes(env.GEMINI_API_KEY));
 assert.ok(!captured.body.includes(env.GEMINI_API_KEY));
});
test('empty model response fails closed',async()=>{
 await assert.rejects(geminiReview('x',env,async()=>({ok:true,json:async()=>({candidates:[]})})));
});
