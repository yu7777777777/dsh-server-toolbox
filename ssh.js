import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { redact, safeOutput } from './secrets.js';
const require=createRequire(import.meta.url);
const fingerprint=key=>'SHA256:'+createHash('sha256').update(key).digest('base64').replace(/=+$/,'');

// Validate without a passphrase and never include parser diagnostics or input in errors.
export function validatePrivateKey(value) {
  const invalid=()=>new Error('私钥无效或带有额外口令；请导入受支持的未加密私钥，不要使用公钥。');
  if(typeof value!=='string'||!value||Buffer.byteLength(value,'utf8')>32768)throw new Error('请输入不超过 32768 UTF-8 字节的未加密私钥。');
  const normalized=value.replace(/^\uFEFF/,'').trim()+'\n';
  if(Buffer.byteLength(normalized,'utf8')>32768)throw invalid();
  let parsed;
  try {parsed=require('ssh2').utils.parseKey(normalized);} catch {throw invalid();}
  const keys=Array.isArray(parsed)?parsed:[parsed];
  if(keys.length!==1||!keys[0]||keys[0] instanceof Error||typeof keys[0].isPrivateKey!=='function'||!keys[0].isPrivateKey())throw invalid();
  return normalized;
}

export async function sshOperation(server, {password, privateKey, trusted, probe=false, command, timeoutSeconds=20, signal}={}) {
  if(server.auth==='config') throw new Error('SSH Config 别名仍可登记，但内置连接仅支持密码、私钥与 SSH Agent。');
  if(!Number.isInteger(timeoutSeconds)||timeoutSeconds<3||timeoutSeconds>60)throw new Error('超时必须为 3–60 秒');
  const active=()=>{if(signal?.aborted)throw new Error('SSH 操作已取消；已开始的远端命令不保证停止。');};
  active();
  if(!probe&&!trusted) throw new Error('请先在工具箱获取主机指纹，并由你核对确认。');
  if(!probe&&server.auth==='password'&&!password) throw new Error('尚未保存登录密码，请在工具箱专用密码框设置。');
  const {Client}=require('ssh2');
  const options={host:server.host,port:server.port,username:server.user,readyTimeout:Math.min(15000,timeoutSeconds*1000),tryKeyboard:false};
  let resolvedKey;
  if(!probe){
    if(server.auth==='password'){options.password=password;options.tryKeyboard=true;}
    else if(server.auth==='key'){
      const mode=server.identityMode??(server.identityFile?'path':'stored');
      if(mode==='stored'){
        if(typeof privateKey!=='string'||!privateKey)throw new Error('尚未保存已导入私钥；不会回退读取密钥路径。');
        resolvedKey=validatePrivateKey(privateKey);
      }else if(mode==='path'){
        let file;
        try {file=await readFile(server.identityFile,{signal});} catch {active();throw new Error('无法读取本机私钥文件，请检查原路径。');}
        active();resolvedKey=validatePrivateKey(file.toString('utf8'));
      }else throw new Error('密钥保存方式无效。');
      options.privateKey=resolvedKey;
    }else options.agent=process.env.SSH_AUTH_SOCK||(process.platform==='win32'?'\\\\.\\pipe\\openssh-ssh-agent':undefined);
  }
  active();
  const secrets=[password,privateKey,resolvedKey];
  return new Promise((resolve,reject)=>{
    const client=new Client();let done=false,observed,truncated=false,outputBytes=0;const buffers=[];
    const timer=setTimeout(()=>finish(new Error('SSH 操作超时；命令可能已在远端启动，请先检查状态，勿盲目重试。')),timeoutSeconds*1000);
    const aborted=()=>finish(new Error('SSH 操作已取消；已开始的远端命令不保证停止。'));
    function finish(error,value){if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',aborted);client.destroy();error?reject(new Error(redact(error.message,secrets))):resolve(value);}
    options.hostVerifier=key=>{
      observed=fingerprint(key);
      if(probe){queueMicrotask(()=>finish(null,{fingerprint:observed,host:server.host,port:server.port,authenticated:false}));return false;}
      return observed===trusted;
    };
    client.on('keyboard-interactive',(_n,_i,_l,prompts,respond)=>{if(server.auth==='password'&&prompts.length===1&&!prompts[0].echo)respond([password]);else{respond([]);finish(new Error('服务器要求额外认证（如 OTP）；本版不支持此认证流程。'));}});
    client.on('error',e=>{if(probe&&observed)return;const message=observed&&trusted!==observed?'主机指纹与已信任记录不一致，已拒绝连接；请核实服务器身份。':e.level==='client-authentication'?'SSH 认证失败，请检查用户名、凭证或服务器登录策略。':e.code==='ECONNREFUSED'?'SSH 端口拒绝连接。':e.code==='ENOTFOUND'?'无法解析主机地址。':'SSH 连接失败，请检查地址、端口、认证方式和网络。';finish(new Error(message));});
    client.on('close',()=>{if(!done)finish(new Error('SSH 连接提前关闭；执行结果未知。'));});
    client.on('ready',()=>{
      if(command===undefined)return finish(null,{connected:true,authenticated:true,fingerprint:observed});
      client.exec(command,{pty:false},(err,stream)=>{
        if(err)return finish(new Error('远程命令启动失败。'));
        const append=b=>{const room=65536-outputBytes;if(room<=0){truncated=true;return;}const chunk=Buffer.from(b);if(chunk.length>room)truncated=true;const kept=chunk.subarray(0,room);buffers.push(kept);outputBytes+=kept.length;};
        stream.on('data',append);stream.stderr.on('data',append);stream.on('error',()=>finish(new Error('远程输出流失败，执行结果未知。')));
        stream.on('close',(code,remoteSignal)=>finish(null,{connected:true,exitCode:code??null,signal:typeof remoteSignal==='string'?redact(remoteSignal,secrets):null,...safeOutput(buffers,secrets,truncated)}));
      });
    });
    if(signal?.aborted)return aborted();signal?.addEventListener('abort',aborted,{once:true});
    try{client.connect(options);}catch{finish(new Error('SSH 连接配置无效。'));}
  });
}
