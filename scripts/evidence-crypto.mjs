// AES-256-GCM evidence envelope. Key supplied at runtime; never logged.
import {createCipheriv,createDecipheriv,randomBytes,createHash} from 'node:crypto';
import {writeFileSync,readFileSync} from 'node:fs';
export function encryptEvidence(record,keyHex){
 if(!/^[a-fA-F0-9]{64}$/.test(keyHex||'')) throw Error('Invalid evidence key');
 const key=Buffer.from(keyHex,'hex'),iv=randomBytes(12);
 const plain=Buffer.from(JSON.stringify(record),'utf8');
 const cipher=createCipheriv('aes-256-gcm',key,iv);
 const encrypted=Buffer.concat([cipher.update(plain),cipher.final()]);
 const tag=cipher.getAuthTag();
 return {schema:'hq-evidence-aes256gcm-v1',iv:iv.toString('base64'),tag:tag.toString('base64'),ciphertext:encrypted.toString('base64'),sha256:createHash('sha256').update(plain).digest('hex')};
}
export function decryptEvidence(envelope,keyHex){
 if(!/^[a-fA-F0-9]{64}$/.test(keyHex||'')) throw Error('Invalid evidence key');
 const decipher=createDecipheriv('aes-256-gcm',Buffer.from(keyHex,'hex'),Buffer.from(envelope.iv,'base64'));
 decipher.setAuthTag(Buffer.from(envelope.tag,'base64'));
 const plain=Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext,'base64')),decipher.final()]);
 if(createHash('sha256').update(plain).digest('hex')!==envelope.sha256) throw Error('Digest mismatch');
 return JSON.parse(plain.toString('utf8'));
}
