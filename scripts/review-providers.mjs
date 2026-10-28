// Provider-neutral interface. No provider credentials are written to disk or logs.
export function validateProviderConfig(env=process.env) {
 const provider=env.REVIEW_PROVIDER||'ollama';
 if(!['ollama','openai-compatible'].includes(provider)) throw Error('Unsupported provider');
 const model=env.REVIEW_MODEL;
 if(!model||!/^[A-Za-z0-9_.:\/-]{1,120}$/.test(model)) throw Error('Invalid model identifier');
 if(provider==='openai-compatible'&&!env.REVIEW_API_KEY) throw Error('Missing API key');
 const endpoint=provider==='ollama'?(env.OLLAMA_URL||'http://127.0.0.1:11434'):env.REVIEW_API_URL;
 if(!endpoint) throw Error('Missing endpoint');
 const url=new URL(endpoint);
 if(provider==='ollama'&&!['localhost','127.0.0.1','[::1]'].includes(url.hostname)) throw Error('Ollama must be loopback');
 if(provider==='openai-compatible'&&url.protocol!=='https:') throw Error('Cloud endpoint must use HTTPS');
 if(provider==='openai-compatible'&&(/^(localhost|127\\.|0\\.|10\\.|192\\.168\\.|169\\.254\\.)/i.test(url.hostname)||url.hostname.endsWith('.local'))) throw Error('Private network endpoint forbidden');
 if(url.username||url.password||url.search||url.hash) throw Error('Endpoint must not embed credentials');
 return {provider,model,url};
}
export async function generateReview(prompt,env=process.env) {
 const cfg=validateProviderConfig(env);
 const ctrl=new AbortController();
 const timer=setTimeout(()=>ctrl.abort(),120000);
 try {
  const isLocal=cfg.provider==='ollama';
  const endpoint=isLocal?new URL('/api/generate',cfg.url):new URL(cfg.url.href.replace(/\/$/,'')+'/chat/completions');
  const headers={'content-type':'application/json'};
  if(!isLocal) headers.authorization='Bearer '+env.REVIEW_API_KEY;
  const body=isLocal?{model:cfg.model,prompt,stream:false,options:{temperature:0}}:{model:cfg.model,messages:[{role:'user',content:prompt}],temperature:0,stream:false};
  const res=await fetch(endpoint,{method:'POST',headers,body:JSON.stringify(body),signal:ctrl.signal,redirect:'error'});
  if(!res.ok) throw Error('Provider returned HTTP '+res.status);
  const data=await res.json();
  const output=isLocal?data.response:data.choices?.[0]?.message?.content;
  if(typeof output!=='string'||!output.trim()||(isLocal&&data.done!==true)) throw Error('Incomplete model response');
  return {output,provider:cfg.provider,requestedModel:cfg.model,returnedModel:data.model||null,usage:isLocal?{evalCount:data.eval_count??null}:{totalTokens:data.usage?.total_tokens??null}};
 } finally {clearTimeout(timer)}
}
