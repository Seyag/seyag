import { RelayCoordinator } from "./coordinator";
import { callTool, toolDefinitions } from "./tools";

interface RelayKV {
  get(key:string, type?:"json"):Promise<any>;
  put(key:string, value:string, options?:{expirationTtl?:number}):Promise<void>;
  delete(key:string):Promise<void>;
  list(options:{prefix:string;cursor?:string;limit?:number}):Promise<{keys:Array<{name:string}>;cursor?:string;list_complete?:boolean}>;
}
export interface Env {
  RELAY: RelayKV;
  AUTH: { idFromName(name:string):unknown; get(id:unknown):{fetch(request:Request):Promise<Response>} };
  OWNER_EMAIL: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  HOME_TOKEN: string;
  CHATGPT_REDIRECT_URIS: string;
  MAX_CLIENT_REGISTRATIONS?: string;
}
export { RelayCoordinator };

const json = (value: unknown, status = 200, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });
const now = () => Date.now();
const random = () => crypto.randomUUID().replaceAll("-", "");
const bearer = (r: Request) => r.headers.get("authorization")?.replace(/^Bearer /, "") || "";
const base = (r: Request) => new URL(r.url).origin;
const BODY_LIMIT = 4096;
const QUEUE_PAGE = 50, QUEUE_TOTAL = 100, PENDING_ACTION_QUOTA = 20;
const domain=/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const app=/^[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+$/;
const channel=/^(?:UC[A-Za-z0-9_-]{22}|@[A-Za-z0-9._-]{3,30})$/;
const exact=(value:any,keys:string[])=>!!value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));

async function listKeys(env:Env,prefix:string,cap=QUEUE_TOTAL){const keys:{name:string}[]=[];let cursor:string|undefined,overflow=false;do{const page=await env.RELAY.list({prefix,cursor,limit:Math.min(QUEUE_PAGE,cap-keys.length)});keys.push(...page.keys.slice(0,cap-keys.length));cursor=page.cursor;overflow=keys.length>=cap&&(!page.list_complete||page.keys.length>cap-keys.length);if(page.list_complete!==false&&!cursor)break;}while(cursor&&keys.length<cap);return{keys,overflow};}

async function cappedBody(req: Request, limit = BODY_LIMIT): Promise<Uint8Array | null> {
  if (!req.body) return new Uint8Array();
  const reader = req.body.getReader(), chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  const body = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return body;
}
function parseJson(body: Uint8Array): Record<string, any> { return JSON.parse(new TextDecoder().decode(body)); }
function parseForm(body: Uint8Array): URLSearchParams { return new URLSearchParams(new TextDecoder().decode(body)); }
async function credentialDigest(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

async function audit(env: Env, action: string, outcome: string, detail = "") {
  const id = `${now()}-${random()}`;
  await env.RELAY.put(`audit:${id}`, JSON.stringify({ at: new Date().toISOString(), action, outcome, detail: detail.slice(0, 120) }), { expirationTtl: 60 * 60 * 24 * 90 });
}

async function coordinate(env:Env, body:unknown) {
  const stub=env.AUTH.get(env.AUTH.idFromName("global"));
  return await (await stub.fetch(new Request("https://coordinator/internal", {method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(body)}))).json() as any;
}
async function limited(env: Env, key: string, maximum = 30): Promise<boolean> {
  return !!(await coordinate(env,{op:"rate",key,maximum})).allowed;
}

async function ownerToken(env: Env, token: string) {
  const record = await env.RELAY.get(`access:${token}`, "json") as { email?:string;expires?:number;clientId?:string;redirect?:string } | null;
  if (!record || record.email?.toLowerCase() !== env.OWNER_EMAIL.toLowerCase() || (record.expires || 0) <= now()) return false;
  const client=await env.RELAY.get(`client:${record.clientId}`,"json") as {redirect_uris?:string[]}|null;
  return !!record.redirect && !!client?.redirect_uris?.includes(record.redirect);
}

function allowedRedirects(env:Env):string[]{try{const value=JSON.parse(env.CHATGPT_REDIRECT_URIS);return Array.isArray(value)?value:[];}catch{return [];}}
function validRedirect(value:string,env:Env){try{const url=new URL(value);return url.protocol==="https:"&&!url.username&&!url.password&&!url.hash&&allowedRedirects(env).includes(value);}catch{return false;}}

async function metadata(req: Request) {
  const root = base(req);
  return json({ issuer: root, authorization_endpoint: `${root}/oauth/authorize`, token_endpoint: `${root}/oauth/token`,
    registration_endpoint: `${root}/oauth/register`, response_types_supported: ["code"], grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"] });
}

async function resourceMetadata(req: Request) {
  const root = base(req);
  return json({ resource: `${root}/mcp`, authorization_servers: [root], bearer_methods_supported: ["header"] });
}

async function register(req: Request, env: Env, raw: Uint8Array) {
  const source=req.headers.get("cf-connecting-ip")||"unknown";
  if (!await limited(env, `register:${source}`, 10)) return json({ error:"rate_limited" }, 429);
  let body:Record<string,unknown>; try { body=parseJson(raw); } catch { return json({error:"invalid_client_metadata"},400); }
  const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((x:unknown) => typeof x === "string") as string[] : [];
  if (!uris.length || uris.length>4 || new Set(uris).size!==uris.length || uris.some(x => x.length>500 || !validRedirect(x,env))) return json({ error: "invalid_redirect_uri" }, 400);
  if (!(await coordinate(env,{op:"registration",maximum:Number(env.MAX_CLIENT_REGISTRATIONS||100)})).allowed) return json({error:"registration_limit_reached"},429);
  const clientId = random();
  await env.RELAY.put(`client:${clientId}`, JSON.stringify({ redirect_uris: uris }),{expirationTtl:60*60*24*30});
  return json({ client_id: clientId, client_name: "ChatGPT", redirect_uris: uris, token_endpoint_auth_method: "none" }, 201);
}

async function authorize(req: Request, env: Env) {
  const u = new URL(req.url), clientId = u.searchParams.get("client_id") || "", redirect = u.searchParams.get("redirect_uri") || "", challenge=u.searchParams.get("code_challenge")||"";
  const client = await env.RELAY.get(`client:${clientId}`, "json") as { redirect_uris?: string[] } | null;
  if (!client?.redirect_uris?.includes(redirect) || !validRedirect(redirect,env) || u.searchParams.get("response_type") !== "code" || u.searchParams.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return json({ error: "invalid_request" }, 400);
  const stateId = random();
  await coordinate(env,{op:"put",key:`login:${stateId}`,value:{clientId,redirect,state:u.searchParams.get("state")||"",challenge},ttl:600000});
  const host=new URL(redirect).host.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]!));
  return new Response(`<!doctype html><meta charset="utf-8"><title>Authorize ChatGPT connector</title><h1>Authorize ChatGPT connector?</h1><p>Access will return to <strong>${host}</strong>.</p><p>The connector can read reduced household counts and submit proposals for your review.</p><form method="post" action="/oauth/consent"><input type="hidden" name="state" value="${stateId}"><button>Continue with Google</button></form>`,{headers:{"content-type":"text/html; charset=utf-8","content-security-policy":"default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}});
}

async function consent(req:Request,env:Env,raw:Uint8Array) {
  const form=parseForm(raw),stateId=String(form.get("state")||"");
  if (!(await coordinate(env,{op:"get",key:`login:${stateId}`})).value) return json({error:"invalid_login"},400);
  const callback = `${base(req)}/oauth/google/callback`;
  const google = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  Object.entries({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: callback, response_type: "code", scope: "openid email", state: stateId, prompt: "select_account" }).forEach(([k,v]) => google.searchParams.set(k,v));
  return Response.redirect(google.toString(), 302);
}

async function googleCallback(req: Request, env: Env) {
  const u = new URL(req.url), stateId = u.searchParams.get("state") || "";
  const login = (await coordinate(env,{op:"take",key:`login:${stateId}`})).value as { clientId:string; redirect:string; state:string; challenge:string } | null;
  if (!login || !u.searchParams.get("code")) return json({ error: "invalid_login" }, 400);
  const form = new URLSearchParams({ code: u.searchParams.get("code")!, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
    redirect_uri: `${base(req)}/oauth/google/callback`, grant_type: "authorization_code" });
  const tr = await fetch("https://oauth2.googleapis.com/token", { method:"POST", body:form });
  const tokens = await tr.json() as { access_token?: string };
  const profile = tokens.access_token ? await (await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers:{ authorization:`Bearer ${tokens.access_token}` } })).json() as {email?:string;email_verified?:boolean} : {};
  if (!profile.email_verified || profile.email?.toLowerCase() !== env.OWNER_EMAIL.toLowerCase()) { await audit(env, "oauth-login", "denied"); return json({ error:"access_denied" }, 403); }
  const code = random();
  await coordinate(env,{op:"put",key:`code:${code}`,value:{...login,email:profile.email},ttl:300000});
  const target = new URL(login.redirect); target.searchParams.set("code", code); if (login.state) target.searchParams.set("state", login.state);
  await audit(env, "oauth-login", "allowed");
  return Response.redirect(target.toString(), 302);
}

async function token(req: Request, env: Env, raw: Uint8Array) {
  const f = parseForm(raw), code = String(f.get("code") || ""), verifier = String(f.get("code_verifier") || "");
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return json({error:"invalid_grant"},400);
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hash))).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
  const bindings={clientId:String(f.get("client_id")||""),redirect:String(f.get("redirect_uri")||""),challenge};
  const rec=(await coordinate(env,{op:"take",key:`code:${code}`,bindings})).value as {clientId:string;redirect:string;email:string}|null;
  if (!rec) return json({ error:"invalid_grant" }, 400);
  const client=await env.RELAY.get(`client:${rec.clientId}`,"json") as {redirect_uris?:string[]}|null;
  if (!client?.redirect_uris?.includes(rec.redirect)) return json({error:"invalid_grant"},400);
  const access = random();
  await env.RELAY.put(`access:${access}`, JSON.stringify({ email:rec.email, clientId:rec.clientId, redirect:rec.redirect, expires:now()+3600000 }), { expirationTtl:3600 });
  return json({ access_token:access, token_type:"Bearer", expires_in:3600 });
}

async function mcp(req: Request, env: Env, raw: Uint8Array) {
  const access=bearer(req);
  if (!await ownerToken(env, access)) return json({ error:"unauthorized" }, 401, { "www-authenticate":`Bearer resource_metadata="${base(req)}/.well-known/oauth-protected-resource"` });
  if (!await limited(env, `mcp:${await credentialDigest(access)}`)) return json({ error:"rate_limited" }, 429);
  let rpc: {id?:unknown;method?:string;params?:{name?:string;arguments?:Record<string,unknown>}};
  try { rpc = parseJson(raw); } catch { return json({error:"invalid_request"},400); }
  let result: unknown;
  if (rpc.method === "initialize") result = { protocolVersion:"2025-03-26", capabilities:{ tools:{} }, serverInfo:{ name:"ai-filter-relay", version:"1.0.0" } };
  else if (rpc.method === "notifications/initialized") return new Response(null, { status:202 });
  else if (rpc.method === "tools/list") result = { tools:toolDefinitions() };
  else if (rpc.method === "tools/call") {
    try { result=await callTool(rpc.params?.name||"",rpc.params?.arguments||{}, {
      getSummary:async()=>await env.RELAY.get("summary","json")||{status:"unavailable",counts:{}},
      enqueueProposal:async proposal=>{const id=random();await env.RELAY.put(`proposal:${now()}:${id}`,JSON.stringify({id,...proposal,created:new Date().toISOString(),status:"pending"}),{expirationTtl:2592000});await audit(env,"proposal","accepted",`${proposal.kind}:${id}`);return id;},
      enqueueAction:async action=>{const pending=await listKeys(env,"action:",PENDING_ACTION_QUOTA);if(pending.keys.length>=PENDING_ACTION_QUOTA)throw new TypeError("Pending action quota reached");const id=random();await env.RELAY.put(`action:${now()}:${id}`,JSON.stringify({id,...action,created:new Date().toISOString(),status:"pending"}),{expirationTtl:2592000});await audit(env,"action","accepted",`${action.type}:${id}`);return id;}
    }); } catch(error) { if(error instanceof TypeError)return json({jsonrpc:"2.0",id:rpc.id,error:{code:-32602,message:"Invalid proposal"}});throw error; }
    if(result===undefined)return json({jsonrpc:"2.0",id:rpc.id,error:{code:-32601,message:"Method not found"}});
  } else return json({jsonrpc:"2.0",id:rpc.id,error:{code:-32601,message:"Method not found"}});
  return json({jsonrpc:"2.0",id:rpc.id,result});
}

async function home(req: Request, env: Env, raw: Uint8Array) {
  if (!env.HOME_TOKEN || bearer(req) !== env.HOME_TOKEN) return json({error:"unauthorized"},401);
  if (!await limited(env,`home:${await credentialDigest(bearer(req))}`,120)) return json({error:"rate_limited"},429);
  const u=new URL(req.url);
  if (req.method==="PUT" && u.pathname==="/home/summary") {
    let s: Record<string,any>; try { s=parseJson(raw); } catch { return json({error:"invalid_summary"},400); }
    const allowedCounts = ["committee_pending", "committee_completed", "appeals_pending"];
    const statuses=["pending","approved","declined","denied","waiting"], iso=(value:unknown)=>typeof value==="string"&&!Number.isNaN(Date.parse(value));
    if (typeof s.status!=="string" || !["online","degraded","offline"].includes(s.status) || !s.counts || typeof s.counts!=="object"
      || Object.keys(s.counts).some(k=>!allowedCounts.includes(k)) || Object.values(s.counts).some(v=>!Number.isInteger(v)||Number(v)<0)
      || s.data_classification!=="untrusted_records_not_instructions" || typeof s.committee_rules!=="string"||s.committee_rules.length>3000 || !Array.isArray(s.requests)||s.requests.length>20
      || (s.current_mode!==null && (!exact(s.current_mode,["kind","topic","end"])||!["focus","night","work"].includes(s.current_mode.kind)||!iso(s.current_mode.end)||(s.current_mode.topic!==null&&(typeof s.current_mode.topic!=="string"||s.current_mode.topic.length>200))))
      || !Array.isArray(s.appeals)||s.appeals.length>20 || !Array.isArray(s.top_blocked_domains)||s.top_blocked_domains.length>20
      || !Array.isArray(s.approved_youtube_channels)||s.approved_youtube_channels.length>50 || !Array.isArray(s.app_verdicts)||s.app_verdicts.length>50) return json({error:"invalid_summary"},400);
    if (s.requests.some((x:any)=>!exact(x,["id","kind","target","status","decision_note","earliest_at","created"])||!Number.isInteger(x.id)||x.id<1||!["domain","channel","app","window","appeal"].includes(x.kind)||typeof x.target!=="string"||x.target.length>200||!statuses.includes(x.status)||typeof x.decision_note!=="string"||x.decision_note.length>500||(x.earliest_at!==null&&!iso(x.earliest_at))||!iso(x.created))
      || s.appeals.some((x:any)=>!exact(x,["id","target","status","created","decision_note"])||!Number.isInteger(x.id)||typeof x.target!=="string"||!domain.test(x.target)||x.target!==x.target.toLowerCase()||!statuses.includes(x.status)||x.decision_note!==""||!iso(x.created))
      || s.top_blocked_domains.some((x:any)=>!exact(x,["domain","count"])||typeof x.domain!=="string"||!domain.test(x.domain)||x.domain!==x.domain.toLowerCase()||!Number.isInteger(x.count)||x.count<1)
      || s.approved_youtube_channels.some((x:any)=>!exact(x,["id","name"])||typeof x.id!=="string"||!channel.test(x.id)||typeof x.name!=="string"||x.name.length>200)
      || s.app_verdicts.some((x:any)=>!exact(x,["bundle_id","verdict"])||typeof x.bundle_id!=="string"||!app.test(x.bundle_id)||!["allow","block","trusted","textonly"].includes(x.verdict))) return json({error:"invalid_summary"},400);
    const requests=s.requests.map((item:any)=>({id:item.id,kind:item.kind,target:item.target,status:item.status,decision_note:item.decision_note,earliest_at:item.earliest_at,created:item.created}));
    const clean={data_classification:s.data_classification,status:s.status.slice(0,40),counts:s.counts,requests,committee_rules:s.committee_rules,current_mode:s.current_mode&&{kind:s.current_mode.kind,topic:null,end:s.current_mode.end},
      appeals:s.appeals.map((x:any)=>({id:x.id,target:x.target,status:x.status,created:x.created,decision_note:x.decision_note})),
      top_blocked_domains:s.top_blocked_domains.map((x:any)=>({domain:x.domain,count:x.count})),approved_youtube_channels:s.approved_youtube_channels.map((x:any)=>({id:x.id,name:x.name})),app_verdicts:s.app_verdicts.map((x:any)=>({bundle_id:x.bundle_id,verdict:x.verdict}))};
    await env.RELAY.put("summary",JSON.stringify({...clean,updated:new Date().toISOString()})); await audit(env,"summary","updated"); return json({ok:true});
  }
  if (req.method==="GET" && u.pathname==="/home/proposals") {
    const list=await listKeys(env,"proposal:"); const proposals=[];
    for(const k of list.keys) { const p=await env.RELAY.get(k.name,"json"); if(p) proposals.push({...p,queue_key:k.name}); }
    return json({proposals,overflow:list.overflow});
  }
  if (req.method==="DELETE" && u.pathname.startsWith("/home/proposals/")) {
    const key=decodeURIComponent(u.pathname.slice("/home/proposals/".length)); if(!key.startsWith("proposal:")) return json({error:"invalid_key"},400);
    await env.RELAY.delete(key); await audit(env,"proposal","pulled",key.slice(-40)); return json({ok:true});
  }
  if (req.method==="GET" && u.pathname==="/home/actions") { const list=await listKeys(env,"action:");const actions=[];for(const k of list.keys){const a=await env.RELAY.get(k.name,"json");if(a&&typeof a==="object"&&!Array.isArray(a))actions.push({...a,queue_key:k.name});else{await audit(env,"action","rejected","invalid queued item");await env.RELAY.delete(k.name);}}return json({actions,overflow:list.overflow}); }
  if (req.method==="DELETE" && u.pathname.startsWith("/home/actions/")) { const key=decodeURIComponent(u.pathname.slice("/home/actions/".length));if(!key.startsWith("action:"))return json({error:"invalid_key"},400);await env.RELAY.delete(key);await audit(env,"action","pulled",key.slice(-40));return json({ok:true}); }
  return json({error:"not_found"},404);
}

export default { async fetch(req:Request,env:Env):Promise<Response> {
  const p=new URL(req.url).pathname;
  let raw: Uint8Array<ArrayBufferLike> = new Uint8Array();
  if (p==="/oauth/register" || p==="/oauth/consent" || p==="/oauth/token" || p==="/mcp" || p.startsWith("/home/")) {
    const body = await cappedBody(req, p==="/home/summary"&&req.method==="PUT" ? 20_000 : BODY_LIMIT);
    if (body === null) return json({error:"request_too_large"},413);
    raw = body;
  }
  if (p==="/.well-known/oauth-authorization-server" || p==="/.well-known/openid-configuration") return metadata(req);
  if (p==="/.well-known/oauth-protected-resource") return resourceMetadata(req);
  if (p==="/oauth/register"&&req.method==="POST") return register(req,env,raw);
  if (p==="/oauth/authorize"&&req.method==="GET") return authorize(req,env);
  if (p==="/oauth/consent"&&req.method==="POST") return consent(req,env,raw);
  if (p==="/oauth/google/callback") return googleCallback(req,env);
  if (p==="/oauth/token"&&req.method==="POST") return token(req,env,raw);
  if (p==="/mcp"&&req.method==="POST") return mcp(req,env,raw);
  if (p.startsWith("/home/")) return home(req,env,raw);
  return json({service:"ai-filter-relay",status:"ok"});
}};
