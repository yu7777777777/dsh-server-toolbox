// This exact /api route is carried by the authenticated DSH Connection,
// including shell-owned transports. No HTML-global token or raw fetch required.
const endpoint='local-server-toolbox';
const actions=new Set(['list','get','save','delete','credential-set','credential-clear','credential-reveal','identity-set','identity-clear','host-probe','host-trust','test']);
export function createUiRoute(operation) {
  return {path:`/api/${endpoint}`,methods:['POST'],requestBody:'buffered',async fetch(request){
    const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'};
    const response=(rpcId,result)=>new Response(JSON.stringify({type:'server-response',rpcId,result}),{headers});
    const fail=(rpcId,code,message)=>response(rpcId,{ok:false,error:{code,message,details:{}}});
    if(request.method!=='POST')return new Response('method not allowed',{status:405,headers});
    if(request.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/json')return new Response('expected application/json',{status:415,headers});
    let message;
    try {
      const body=await request.text();
      if(Buffer.byteLength(body)>512000)return new Response('request too large',{status:413,headers});
      message=JSON.parse(body);
    }catch{return fail('invalid-request','toolbox/bad-request','请求格式无效，未执行操作。');}
    const id=typeof message?.rpcId==='string'&&message.rpcId.length>0&&message.rpcId.length<=128?message.rpcId:'invalid-request';
    if(message?.type!=='client-request'||id==='invalid-request'||message.method!==endpoint||!message.payload||typeof message.payload!=='object'||Array.isArray(message.payload))return fail(id,'toolbox/bad-request','插件请求协议无效，未执行操作。');
    if(!actions.has(message.payload.action||'list'))return fail(id,'toolbox/forbidden','此页面通道不允许该操作。');
    if(request.signal.aborted)return fail(id,'toolbox/cancelled','操作已取消。');
    try{return response(id,{ok:true,value:await operation(message.payload,'ui',{signal:request.signal})});}
    catch(error){return fail(id,'toolbox/operation-failed',message.payload.action==='credential-reveal'?'无法查看已保存密码，请刷新后重试或重新设置。':['identity-set','identity-clear'].includes(message.payload.action)?'私钥操作失败。请确认使用 Windows，导入的是未加口令的 SSH 私钥（不是公钥或文件夹），且不超过 32 KiB。':error instanceof Error?error.message:'操作失败');}
  }};
}
