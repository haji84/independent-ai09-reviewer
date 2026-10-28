import test from 'node:test';
import assert from 'node:assert/strict';
import {validateProviderConfig} from '../scripts/review-providers.mjs';
test('local provider requires loopback',()=>{
 assert.equal(validateProviderConfig({REVIEW_MODEL:'qwen2.5-coder:3b'}).provider,'ollama');
 assert.throws(()=>validateProviderConfig({REVIEW_MODEL:'x',OLLAMA_URL:'https://example.com'}));
});
test('cloud requires HTTPS and secret',()=>{
 assert.throws(()=>validateProviderConfig({REVIEW_PROVIDER:'openai-compatible',REVIEW_MODEL:'model',REVIEW_API_URL:'http://example.com',REVIEW_API_KEY:'dummy'}));
 assert.throws(()=>validateProviderConfig({REVIEW_PROVIDER:'openai-compatible',REVIEW_MODEL:'model',REVIEW_API_URL:'https://example.com'}));
 assert.equal(validateProviderConfig({REVIEW_PROVIDER:'openai-compatible',REVIEW_MODEL:'model',REVIEW_API_URL:'https://example.com/v1',REVIEW_API_KEY:'dummy'}).provider,'openai-compatible');
});
test('reject embedded credentials',()=>{
 assert.throws(()=>validateProviderConfig({REVIEW_MODEL:'model',OLLAMA_URL:'http://user:pass@localhost:11434'}));
});
