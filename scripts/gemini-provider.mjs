// Gemini native API adapter. No network call unless explicitly invoked.
const HOST='generativelanguage.googleapis.com';
export function geminiConfig(env=process.env) {
 const key=env.GEMINI_API_KEY;
 const model=env.REVIEW_MODEL;
 if(!key) throw Error('GEMINI_API_KEY is required');
 if(!model||!/^[A-Za-z0-9_.-]{1,100}$/.test(model)) throw Error('Invalid Gemini model');
 if(env.REVIEW_ALLOW_PAID!=='false') throw Error('Explicit no-paid policy required');
 return {key,model};
}
export async function geminiReview(prompt,env=process.env,transport=fetch) {
 const {key,model}=geminiConfig(env);
 const url=new URL('https://'+HOST+'/v1beta/models/'+encodeURIComponent(model)+':generateContent');
 const controller=new AbortController();
 const timer=setTimeout(()=>controller.abort(),120000);
 try {
  const response=await transport(url,{method:'POST',headers:{'content-type':'application/json','x-goog-api-key':key},body:JSON.stringify({contents:[{parts:[{text:prompt}]}],generationConfig:{temperature:0,maxOutputTokens:2048}}),signal:controller.signal,redirect:'error'});
  if(!response.ok) throw Error('Gemini request failed HTTP '+response.status);
  const json=await response.json();
  const text=json.candidates?.[0]?.content?.parts?.filter(p=>typeof p.text==='string').map(p=>p.text).join('');
  if(!text?.trim()) throw Error('Gemini returned no text');
  return {output:text,provider:'gemini',requestedModel:model,returnedModel:json.modelVersion||null,usage:{totalTokens:json.usageMetadata?.totalTokenCount??null}};
 } finally {clearTimeout(timer)}
}
