import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { createUiRoute } from './transport.js';
import { credentialAdapter, protect, unprotect } from './secrets.js';
import { sshOperation } from './ssh.js';
import { createApplication } from './application.js';
import { registerTools } from './tools.js';

export const inject = ['tools', 'connection', 'credentials', 'approval'];
const dataFile = fileURLToPath(new URL('./data/servers.json', import.meta.url));
const fields = ['id','name','host','user','port','auth','identityMode','identityFile','sshAlias','notes','expiresOn','services','projects'];
function text(v, max=2000) { if (typeof v !== 'string' || v.length > max || /[\x00-\x08]/.test(v)) throw new Error('字段必须为有效文本'); return v.trim(); }
export function validateServer(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('服务器数据无效');
  for (const k of Object.keys(raw)) if (!fields.includes(k)) throw new Error(`不支持字段 ${k}；不要保存密码或私钥正文`);
  const s = {id:raw.id ? text(raw.id,80) : randomUUID(),name:text(raw.name,120),host:text(raw.host||'',255),user:text(raw.user||'',120),port:Number(raw.port??22),auth:raw.auth||'password',identityFile:text(raw.identityFile||'',1024),sshAlias:text(raw.sshAlias||'',120),notes:text(raw.notes||''),services:[],projects:[]};
  s.expiresOn=raw.expiresOn===undefined?'':text(raw.expiresOn,10);
  if(s.expiresOn){
    const date=new Date(`${s.expiresOn}T00:00:00.000Z`);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(s.expiresOn)||s.expiresOn<'0001-01-01'||!Number.isFinite(date.getTime())||date.toISOString().slice(0,10)!==s.expiresOn)throw new Error('到期日期无效，请选择有效的 YYYY-MM-DD 日期');
  }
  if (!s.name) throw new Error('服务器名称必填');
  if (!['password','agent','key','config'].includes(s.auth)) throw new Error('请选择密码、SSH Agent、密钥路径或 SSH Config');
  if (!Number.isInteger(s.port)||s.port<1||s.port>65535) throw new Error('端口必须为 1–65535');
  if (s.auth==='config') { if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/.test(s.sshAlias)) throw new Error('SSH Config 别名无效'); }
  else if (!/^[a-zA-Z0-9][a-zA-Z0-9.:-]*$/.test(s.host)||!s.user||!/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/.test(s.user)) throw new Error('主机地址与用户名无效');
  s.identityMode=raw.identityMode===undefined?(s.identityFile?'path':'stored'):raw.identityMode;
  if(!['stored','path'].includes(s.identityMode))throw new Error('密钥保存方式必须为 stored 或 path');
  if(s.auth==='key'&&s.identityMode==='path'&&!s.identityFile)throw new Error('密钥路径必填，不要填写私钥正文');
  for (const k of ['services','projects']) {
    if (!Array.isArray(raw[k]||[]) || (raw[k]||[]).length>200) throw new Error('部署项过多或格式错误');
    s[k]=(raw[k]||[]).map(r=>{
      const allowed=k==='services'?['name','url','directory','notes']:['name','directory','notes'];
      if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).some(key=>!allowed.includes(key)))throw new Error('服务只支持名称、网址及历史兼容字段');
      const item={name:text(r.name,120)};if(!item.name)throw new Error('部署名称必填');
      if(k==='services'){
        item.url=text(r.url||'',2048);
        if(item.url){let parsed;try{parsed=new URL(item.url);}catch{throw new Error('服务网址无效，请填写完整的 http:// 或 https:// 网址');}
          if(!/^https?:\/\//i.test(item.url)||/[\s\\]/.test(item.url)||!['http:','https:'].includes(parsed.protocol)||!parsed.hostname||parsed.username||parsed.password)throw new Error('服务网址只支持不含账号密码的 HTTP/HTTPS 地址');
        }else if(!Object.hasOwn(r,'directory')&&!Object.hasOwn(r,'notes'))throw new Error('服务网址必填');
        // Preserve old metadata without interpreting remote paths as web addresses.
        for(const legacy of ['directory','notes'])if(Object.hasOwn(r,legacy))item[legacy]=text(r[legacy]||'',legacy==='notes'?2000:1024);
      }else{item.directory=text(r.directory||'',1024);item.notes=text(r.notes||'');}
      return item;
    });
  }
  if (/-----BEGIN .*PRIVATE KEY-----|(?:password|passwd|token|secret)\s*[:=]/i.test(JSON.stringify(s))) throw new Error('请勿在服务器元数据中保存密码、Token 或私钥正文');
  return s;
}
export function connection(s) {
  const args=['-o','StrictHostKeyChecking=yes'];
  if(s.auth==='config')args.push(s.sshAlias);
  else { args.push('-p',String(s.port));if(s.auth==='key'&&(s.identityMode??(s.identityFile?'path':'stored'))==='path')args.push('-i',s.identityFile);args.push(`${s.user}@${s.host}`); }
  return {executable:'ssh',args,requiresHostKeyEnrollment:true,executionEnabled:s.auth!=='config',preferredTool:'server_ssh',note:s.auth==='key'&&(s.identityMode??(s.identityFile?'path':'stored'))==='stored'?'已加密导入的私钥仅供 server_ssh 在内存中使用，不提供系统 ssh 的私钥路径；系统 ssh 另用自身 known_hosts。':'系统 ssh 使用自身 known_hosts；插件指纹信任仅供 server_ssh 使用。'};
}
export function createStore(file=dataFile) {
  let queue=Promise.resolve();
  async function load(){try{const state=JSON.parse(await readFile(file,'utf8'));if(state.version!==1||!Array.isArray(state.servers))throw new Error('数据版本无效');state.servers=state.servers.map(validateServer);return state;}catch(e){if(e.code==='ENOENT')return {version:1,revision:0,servers:[]};throw e;}}
  async function operation(args={}) {
    const action=args.action||'list';
    if(action==='list'||action==='get') { const state=await load();if(action==='get'){const s=state.servers.find(s=>s.id===args.id);if(!s)throw new Error('服务器不存在');return {...s,connection:connection(s)};}const q=String(args.query||'').toLowerCase();return {...state,servers:state.servers.filter(s=>JSON.stringify(s).toLowerCase().includes(q))}; }
    const run=queue.then(async()=>{const state=await load();if(args.revision!==state.revision)throw new Error('数据已更新，请刷新后重试');if(action==='save'){const i=state.servers.findIndex(x=>x.id===args.server?.id);const input=i>=0&&args.server.identityMode===undefined?{...args.server,identityMode:state.servers[i].identityMode}:args.server;const s=validateServer(input);if(i<0)state.servers.push(s);else{if(!Object.hasOwn(args.server,'expiresOn'))s.expiresOn=state.servers[i].expiresOn;if(!Object.hasOwn(args.server,'projects'))s.projects=state.servers[i].projects;state.servers[i]=s;}}else if(action==='delete'){if(!state.servers.some(s=>s.id===args.id))throw new Error('服务器不存在');state.servers=state.servers.filter(s=>s.id!==args.id);}else throw new Error('未知操作');state.revision++;const temp=file+'.'+randomUUID()+'.tmp';await mkdir(dirname(file),{recursive:true});await writeFile(temp,JSON.stringify(state,null,2),'utf8');await rename(temp,file);return state;});queue=run.catch(()=>{});return run;
  }
  return operation;
}
export function apply(ctx) {
  const operation=createApplication({store:createStore(),credentials:credentialAdapter(ctx.credentials),protect,unprotect,ssh:sshOperation,approve:async(s,command,exec)=>(await ctx.approval.request({agent:exec.agent,toolName:'server_ssh',callId:exec.callId,reason:`SSH 远程执行 ${s.name} (${s.user}@${s.host}:${s.port})\n${command}`,signal:exec.signal}))==='allowed-once'});
  registerTools(ctx,operation);
  ctx.effect(()=>ctx.connection.fetch.register(createUiRoute(operation)));
}
