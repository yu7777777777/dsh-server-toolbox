import { createHash, randomBytes } from 'node:crypto';

export function binding(s) { return createHash('sha256').update(JSON.stringify([s.id,s.host,s.port,s.user,s.auth==='config'?s.sshAlias:''])).digest('hex'); }
const key=(s,kind)=>`server-toolbox/${kind}-${binding(s)}`;
export function createApplication({store,credentials,protect,unprotect,ssh,approve}) {
  const pending=new Map();let tail=Promise.resolve();
  const serial=fn=>{const p=tail.then(fn);tail=p.catch(()=>{});return p;};
  async function decorate(s){const {connection,...raw}=s;return {...raw,passwordConfigured:await credentials.has(key(s,'password')),trustedFingerprint:(await credentials.get(key(s,'host')))?.fingerprint||null,...(connection?{connection}: {})};}
  async function read(id){return store({action:'get',id});}
  async function runSSH(args,exec={}) {
    const s=await read(args.id);
    const pin=await credentials.get(key(s,'host'));
    if(!pin?.fingerprint)throw new Error('请在服务器工具箱中获取并核对主机指纹，再由你确认信任。');
    if(!['test','run'].includes(args.action))throw new Error('不支持的 SSH 操作');
    let command;
    if(args.action==='run'){
      if(typeof args.command!=='string'||!args.command.trim()||args.command.length>16000||args.command.includes('\0'))throw new Error('命令必须为非空文本且不超过 16000 字符');
      command=args.command;
      if(!exec.agent)throw new Error('远程执行必须属于一个受权限检查的 DSH 会话');
      if(!await approve(s,command,exec))throw new Error('远程命令未获得本次执行授权；未发起 SSH 连接。');
    }
    return serial(async()=>{
      const current=await read(args.id);
      if(binding(current)!==binding(s)||JSON.stringify(current)!==JSON.stringify(s))throw new Error('服务器记录在授权期间发生变化，请重新发起。');
      const activePin=await credentials.get(key(current,'host'));
      if(activePin?.fingerprint!==pin.fingerprint)throw new Error('主机信任记录已变更，请重新发起。');
      let password;
      if(current.auth==='password'){
        const record=await credentials.get(key(current,'password'));
        if(!record?.encrypted)throw new Error('请先在插件专用密码框保存登录密码。');
        password=await unprotect(record.encrypted);
      }
      const seconds=args.timeoutSeconds??20;
      if(!Number.isInteger(seconds)||seconds<3||seconds>60)throw new Error('超时必须为 3–60 秒');
      return ssh(current,{password,trusted:pin.fingerprint,command,timeoutSeconds:seconds,signal:exec.signal});
    });
  }
  async function operation(args={},caller='agent',exec={}) {
    if(['credential-set','credential-clear','credential-reveal','host-probe','host-trust'].includes(args.action)){
      if(caller!=='ui')throw new Error('密码与主机信任只能由用户在插件界面管理。');
      return serial(async()=>{
        const s=await read(args.id);
        if(args.revision!==(await store({action:'list'})).revision)throw new Error('数据已更新，请刷新后重试');
        if(args.action==='credential-set'){
          if(s.auth!=='password')throw new Error('请先选择密码认证并保存服务器');
          if(typeof args.password!=='string'||!args.password||args.password.length>1024)throw new Error('请输入不超过 1024 字符的密码');
          const encrypted=await protect(args.password);
          await credentials.set(key(s,'password'),{encrypted});
          return {saved:true};
        }
        if(args.action==='credential-reveal'){
          if(args.confirmed!==true)throw new Error('请先在页面确认查看密码。');
          if(s.auth!=='password')throw new Error('该服务器未使用密码认证。');
          exec.signal?.throwIfAborted();
          const record=await credentials.get(key(s,'password'));
          if(!record?.encrypted)throw new Error('该服务器未保存登录密码。');
          let password;
          try{password=await unprotect(record.encrypted);}catch{throw new Error('无法解密已保存密码，请确认仍使用原 Windows 用户，或重新设置密码。');}
          exec.signal?.throwIfAborted();
          if(typeof password!=='string'||!password||password.length>1024)throw new Error('已保存密码格式无效，请重新设置。');
          return {password};
        }
        if(args.action==='credential-clear'){await credentials.delete(key(s,'password'));return {cleared:true};}
        if(args.action==='host-probe'){
          for(const [id,v] of pending)if(v.expires<Date.now())pending.delete(id);
          const probe=await ssh(s,{probe:true,timeoutSeconds:15});
          if(pending.size>=100)pending.delete(pending.keys().next().value);
          const challenge=randomBytes(24).toString('hex');pending.set(challenge,{binding:binding(s),fingerprint:probe.fingerprint,expires:Date.now()+300000});
          return {...probe,challenge,previousFingerprint:(await credentials.get(key(s,'host')))?.fingerprint||null};
        }
        const challenge=pending.get(args.challenge);pending.delete(args.challenge);
        if(!challenge||challenge.expires<Date.now()||challenge.binding!==binding(s))throw new Error('主机指纹确认已过期或连接资料发生变化，请重新获取。');
        await credentials.set(key(s,'host'),{fingerprint:challenge.fingerprint});
        return {trusted:true,fingerprint:challenge.fingerprint};
      });
    }
    if(args.action==='test')return runSSH(args,exec);
    if(args.action==='run'){
      if(caller!=='agent')throw new Error('页面不提供远程命令执行，请通过有权限检查的 DSH 工具调用。');
      return runSSH(args,exec);
    }
    if(!['list','get','save','delete'].includes(args.action||'list'))throw new Error('未知操作');
    return serial(async()=>{
      let before;
      if(['save','delete'].includes(args.action)){
        const all=await store({action:'list'});before=all.servers.find(s=>s.id===(args.server?.id||args.id));
      }
      const result=await store(args);
      if(before&&['save','delete'].includes(args.action)){
        const after=args.action==='save'?result.servers.find(s=>s.id===before.id):undefined;
        if(!after||binding(after)!==binding(before))for(const kind of ['password','host'])await credentials.delete(key(before,kind));
      }
      if(result.servers)return {...result,servers:await Promise.all(result.servers.map(decorate))};
      return decorate(result);
    });
  }
  return operation;
}
