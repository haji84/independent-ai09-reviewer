import test from 'node:test';
import assert from 'node:assert/strict';
import {encryptEvidence,decryptEvidence} from '../scripts/evidence-crypto.mjs';
const key='a'.repeat(64);
test('encrypted evidence roundtrip',()=>{const obj={model:'synthetic',response:'private synthetic finding'};const e=encryptEvidence(obj,key);assert.ok(!JSON.stringify(e).includes(obj.response));assert.deepEqual(decryptEvidence(e,key),obj);});
test('wrong key or tampering fails closed',()=>{const e=encryptEvidence({x:1},key);assert.throws(()=>decryptEvidence(e,'b'.repeat(64)));e.ciphertext='AAAA';assert.throws(()=>decryptEvidence(e,key));});
test('missing or malformed key rejected',()=>assert.throws(()=>encryptEvidence({x:1},'')));
