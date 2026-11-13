import { spawn } from 'node:child_process';
import { join } from 'node:path';
import { StringDecoder } from 'node:string_decoder';

// Windows DPAPI CurrentUser: secrets travel over stdin, never command arguments.
export function dpapi(value, decrypt = false) {
  if (process.platform !== 'win32') return Promise.reject(new Error('本版凭证保存需要 Windows DPAPI；不支持时不会降级为明文。'));
  return new Promise((resolve, reject) => {
    const method = decrypt ? 'Unprotect' : 'Protect';
    const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; $s=[Console]::In.ReadToEnd(); $b=[Convert]::FromBase64String($s); $r=[System.Security.Cryptography.ProtectedData]::${method}($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($r))`;
    const child = spawn(join(process.env.SystemRoot || 'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe'), ['-NoProfile','-NonInteractive','-Command',script], {windowsHide:true,stdio:['pipe','pipe','ignore']});
    let output='', done=false;
    const timer=setTimeout(()=>{child.kill();finish(new Error('Windows 凭证加解密超时'));},15000);
    function finish(err,result){if(done)return;done=true;clearTimeout(timer);err?reject(err):resolve(result);}
    child.on('error',()=>finish(new Error('无法启动 Windows DPAPI；未保存明文。')));
    child.stdin.on('error',()=>{});
    child.stdout.on('data',b=>{output+=b;if(output.length>65536){child.kill();finish(new Error('Windows 凭证处理失败'));}});
    child.on('close',code=>{if(code!==0)return finish(new Error('Windows 凭证加解密失败；请使用原 Windows 用户。'));const s=output.trim();if(!/^[A-Za-z0-9+/=]+$/.test(s))return finish(new Error('Windows 凭证返回值无效'));finish(null,decrypt?Buffer.from(s,'base64').toString('utf8'):'dpapi:v1:'+s);});
    if(decrypt){if(typeof value!=='string'||!value.startsWith('dpapi:v1:')){child.kill();finish(new Error('凭证格式不支持'));return;}child.stdin.end(value.slice(9));}
    else child.stdin.end(Buffer.from(value,'utf8').toString('base64'));
  });
}
export const protect = value => dpapi(value);
export const unprotect = value => dpapi(value,true);

function secretVariants(secret) {
  const variants=new Set();
  for(const value of Array.isArray(secret)?secret:[secret]){
    if(typeof value!=='string'||!value)continue;
    const raw=[value];
    if(/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)){
      raw.push(value.replace(/\r\n/g,'\n'),value.trim());
      const lines=value.split(/\r?\n/).filter(line=>/^[A-Za-z0-9+/=]{20,}$/.test(line));
      raw.push(...lines,lines.join(''));
    }
    for(const s of raw)if(s){variants.add(s);variants.add(Buffer.from(s).toString('base64'));variants.add(encodeURIComponent(s));}
  }
  return [...variants].sort((a,b)=>b.length-a.length);
}
export function redact(text, secret) {
  let value=String(text);
  for(const s of secretVariants(secret))value=value.split(s).join('[REDACTED]');
  return value;
}
export function safeOutput(buffers, secret, truncated, limit=65536) {
  let text=new StringDecoder('utf8').write(Buffer.concat(buffers));
  const variants=secretVariants(secret);
  if(truncated){
    for(const variant of variants){
      if(text.endsWith(variant))continue;
      for(let n=Math.min(variant.length-1,text.length);n>0;n--)if(text.endsWith(variant.slice(0,n))){text=text.slice(0,-n);break;}
    }
  }
  for(const s of variants)text=text.split(s).join('[REDACTED]');
  const bytes=Buffer.from(text,'utf8');
  return {output:new StringDecoder('utf8').write(bytes.subarray(0,limit)),truncated:truncated||bytes.length>limit};
}
export function credentialAdapter(credentials) {
  return {
    async has(key){return (await credentials.describeRecord(key)).configured;},
    async get(key){const record=await credentials.readRecord(key);return record?.kind==='grant'?record.payload:undefined;},
    async set(key,value){await credentials.modifyRecord(key,async()=>({kind:'grant',payload:value}));},
    async delete(key){await credentials.deleteRecord(key);},
  };
}
