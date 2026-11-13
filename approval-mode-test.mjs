import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createStore,validateServer,normalizeSettings,readSessionPolicy} from './index.js';
import {createApplication} from './application.js';

const dir=await mkdtemp(join(tmpdir(),'dsh-approval-mode-test-'));
try {
 const file=join(dir,'servers.json'),store=createStore(file),records=new Map();
 const credentials={async has(k){return records.has(k);},async get(k){return records.get(k);},async set(k,v){records.set(k,v);},async delete(k){records.delete(k);}};
 const saved=await store({action:'save',revision:0,server:{name:'Approval synthetic',host:'example.test',user:'deploy',port:22,auth:'password',services:[],projects:[]}});
 const id=saved.servers[0].id,guard={async has(){return true;},async get(k){return String(k).includes('password')?{encrypted:'dpapi:v1:stub'}:{fingerprint:'SHA256:TEST'};},async set(){},async delete(){}};
 const secretRecord={encrypted:'dpapi:v1:stub'};
 let sshCalls=0,approveCalls=0,allowApprove=false,policyResult,policyError,currentPolicy;
 const app=createApplication({store,credentials:guard,protect:async v=>'dpapi:v1:'+v,unprotect:async()=>'SYNTHETIC',ssh:async()=>{sshCalls++;return {connected:true,exitCode:0,output:'ok'};},approve:async()=>{approveCalls++;return allowApprove;},sessionPolicy:async()=>{if(policyError)throw policyError;return policyResult;}});
 const exec={agent:{id:'synthetic-agent'},callId:'call-1'};

 // Defaults and validation.
 assert.deepEqual(normalizeSettings(undefined),{approval:'ask'});
 assert.deepEqual(normalizeSettings({approval:'follow-session'}),{approval:'follow-session'});
 assert.deepEqual(normalizeSettings({approval:'bogus'}),{approval:'ask'});
 assert.deepEqual((await store({action:'settings-get'})).settings,{approval:'ask'});
 await assert.rejects(app({action:'settings-set',revision:1,settings:{approval:'follow-session'}},'agent'),/只能由用户/);
 await assert.rejects(app({action:'settings-set',revision:1,settings:{approval:'bogus'}},'ui'),/无效/);
 await assert.rejects(app({action:'settings-set',revision:99,settings:{approval:'follow-session'}},'ui'),/更新/);

 // Default mode always asks, and a refusal blocks before any connection.
 await assert.rejects(app({action:'run',id,command:'echo ok'},'agent',exec),/未获得/);
 assert.equal(approveCalls,1);assert.equal(sshCalls,0);
 allowApprove=true;const first=await app({action:'run',id,command:'echo ok'},'agent',exec);
 assert.equal(first.approvedBy,'per-call');assert.equal(sshCalls,1);

 // Follow-session still asks when the session is not full-access-without-approval.
 await app({action:'settings-set',revision:1,settings:{approval:'follow-session'}},'ui');
 for(const policy of [{approval:'ask',sandbox:'danger-full-access'},{approval:'never',sandbox:'workspace-write'},{approval:'never',sandbox:'read-only'},undefined]){
   policyResult=policy;const before=approveCalls,connections=sshCalls;
   await app({action:'run',id,command:'echo ok'},'agent',exec);
   assert.equal(approveCalls,before+1,'every non-matching session must still ask');
   assert.equal(sshCalls,connections+1);
 }
 policyError=new Error('permission lookup failed');const guarded=approveCalls;
 await app({action:'run',id,command:'echo ok'},'agent',exec);
 assert.equal(approveCalls,guarded+1,'a lookup failure must fall back to asking');policyError=undefined;

 // A refusal still blocks even in follow-session mode.
 policyResult={approval:'ask',sandbox:'danger-full-access'};allowApprove=false;const blocked=sshCalls;
 await assert.rejects(app({action:'run',id,command:'echo ok'},'agent',exec),/未获得/);assert.equal(sshCalls,blocked);allowApprove=true;

 // Only full access with approvals off skips the prompt, and the result states why.
 policyResult={approval:'never',sandbox:'danger-full-access',preset:'full-access'};
 const skippedFrom=approveCalls;
 const auto=await app({action:'run',id,command:'echo ok'},'agent',exec);
 assert.equal(approveCalls,skippedFrom,'no prompt when the session already allows execution');
 assert.equal(auto.approvedBy,'session-policy');assert.equal(auto.sessionPreset,'full-access');
 assert.equal((await app({action:'test',id},'agent',exec)).authenticated ?? true,true);

 // Host trust stays mandatory even when the session policy would skip the prompt.
 const noCreds={async has(){return false;},async get(){return undefined;},async set(){},async delete(){}};
 const untrusted=createApplication({store,credentials:noCreds,protect:async()=>'',unprotect:async()=>'',ssh:async()=>{throw Error('must not connect');},approve:async()=>{throw Error('must not ask');},sessionPolicy:async()=>({approval:'never',sandbox:'danger-full-access',preset:'full-access'})});
 await assert.rejects(untrusted({action:'run',id,command:'echo ok'},'agent',exec),/指纹/);

 // The setting persists, and a corrupted file falls back to asking.
 const reread=await createStore(file)({action:'settings-get'});
 assert.equal(reread.settings.approval,'follow-session');
 const raw=JSON.parse(await readFile(file,'utf8'));raw.settings={approval:'nonsense'};
 await (await import('node:fs/promises')).writeFile(file,JSON.stringify(raw));
 assert.equal((await createStore(file)({action:'settings-get'})).settings.approval,'ask');

 // Session policy resolution fails closed outside a real Host runtime.
 assert.equal(readSessionPolicy({},{agent:{id:'x'}}),undefined);
 assert.equal(readSessionPolicy({get:()=>undefined},{agent:{id:'x'}}),undefined);
 assert.equal(readSessionPolicy({get:()=>{throw new Error('no ctx');}},{agent:{id:'x'}}),undefined);
 assert.equal(readSessionPolicy({get:name=>name==='sessions'?{get:()=>({})}:name==='permissionPresets'?{current:()=>'full-access',resolve:()=>({approval:'never',sandbox:'danger-full-access'})}:undefined},{agent:{id:'x'}}).approval,'never');
 assert.equal(readSessionPolicy({get:name=>name==='sessions'?{get:()=>undefined}:{current:()=>'x',resolve:()=>({})}},{agent:{id:'x'}}),undefined);
} finally { await rm(dir,{recursive:true,force:true}); }
console.log('PASS: settings default/validation, UI-only writes, per-call approval preserved, follow-session skips only for full-access-with-approvals-off, refusal and lookup failure still ask, persisted setting, corrupted-value fallback and fail-closed session resolution.');
