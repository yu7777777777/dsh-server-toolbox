import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
const source=await readFile(new URL('./client.js',import.meta.url),'utf8');
const secret='SYNTHETIC-VIEW-ONLY-SECRET';
const sample={id:'synthetic',name:'Synthetic',host:'example.test',user:'deploy',port:22,auth:'password',services:[],notes:'',expiresOn:'',passwordConfigured:true};
const labels={},calls=[],requests=[],timers=new Map();let timerId=0,Page,current;
function target(){const events=new Map();return {addEventListener(name,fn){if(!events.has(name))events.set(name,new Set());events.get(name).add(fn);},removeEventListener(name,fn){events.get(name)?.delete(fn);},emit(name){for(const fn of [...events.get(name)||[]])fn();},listenerCount(){return [...events.values()].reduce((n,s)=>n+s.size,0);}};}
const document={...target(),hidden:false},window={...target()};
const React={Fragment:'fragment',createElement:(type,props,...children)=>({type,props:props||{},children:children.flat(Infinity)}),useSyncExternalStore:()=>{},
 useState(initial){const f=current,i=f.cursor++;if(!(i in f.slots))f.slots[i]=f.root&&i===0?{revision:7,servers:[sample]}:f.root&&i===1?{...sample,passwordConfigured:undefined}:initial;return [f.slots[i],value=>{f.slots[i]=typeof value==='function'?value(f.slots[i]):value;}];},
 useRef(initial){const f=current,i=f.cursor++;if(!(i in f.slots))f.slots[i]={current:initial};return f.slots[i];},
 useEffect(fn,deps){const f=current,i=f.cursor++;if(f.root)return;const old=f.slots[i];if(!old||!deps||deps.some((v,j)=>!Object.is(v,old.deps[j]))){f.pending.push(()=>{old?.cleanup?.();f.slots[i]={deps,cleanup:fn()};});}}
};
window.__ModuleLoader__={load:definition=>definition.factory(()=>React).apply({effect:fn=>fn(),locale:{register:(_ns,language,values)=>{if(language==='zh')Object.assign(labels,values);return()=>{};},bind:()=>key=>labels[key],subscribe:()=>{},getSnapshot:()=>0},slots:{inject:(_slot,fn)=>fn(),register:(meta,component)=>{if(meta.name==='main')Page=component;}},connection:{rpc:{call:(...args)=>{calls.push(args);return new Promise(resolve=>requests.push(resolve));}}}})};
runInNewContext(source,{window,document,AbortController,setTimeout:(fn,ms)=>{assert.equal(ms,15000);const id=++timerId;timers.set(id,fn);return id;},clearTimeout:id=>timers.delete(id)});
function frame(component,props={},root=false){const f={component,props,root,slots:[],cursor:0,pending:[],mounted:true};f.render=()=>{if(!f.mounted)return null;current=f;f.cursor=0;f.pending=[];const tree=component(f.props);for(const fn of f.pending)fn();return tree;};f.unmount=()=>{f.mounted=false;for(const slot of f.slots)slot?.cleanup?.();};return f;}
function nodes(tree){const out=[];function walk(n){if(!n||typeof n!=='object')return;out.push(n);for(const child of n.children||[])walk(child);}walk(tree);return out;}
const root=frame(Page,{},true),componentNode=nodes(root.render()).find(n=>typeof n.type==='function'&&n.type.name==='PasswordReveal');assert.ok(componentNode);
function makeView(){return frame(componentNode.type,componentNode.props);}
const readout=tree=>nodes(tree).find(n=>n.type==='input'&&n.props.readOnly);
const click=(tree,label)=>{const b=nodes(tree).find(n=>n.type==='button'&&n.children.includes(label));assert.ok(b,'Missing expected UI control');return b.props.onClick();};
async function shown(view){click(view.render(),labels.viewSecret);const pending=click(view.render(),labels.confirmReveal);requests.shift()({ok:true,value:{password:secret}});await pending;const tree=view.render();assert.equal(readout(tree)?.props.value,secret);assert.equal(root.slots[2],'');return tree;}
const view=makeView();assert.equal(calls.length,0);assert.equal(readout(view.render()),undefined);assert.equal(calls.length,0);
click(view.render(),labels.viewSecret);click(view.render(),labels.cancel);assert.equal(calls.length,0);
await shown(view);assert.equal(calls.length,1);assert.equal(calls[0][2].action,'credential-reveal');assert.equal(calls[0][2].confirmed,true);assert.equal(calls[0][2].revision,7);assert.equal(timers.size,1);
for(const [id,fn] of [...timers]){timers.delete(id);fn();}assert.equal(readout(view.render()),undefined);
await shown(view);click(view.render(),labels.hideSecret);assert.equal(timers.size,0);assert.equal(readout(view.render()),undefined);
await shown(view);window.emit('blur');assert.equal(readout(view.render()),undefined);assert.equal(timers.size,0);
await shown(view);document.hidden=true;document.emit('visibilitychange');assert.equal(readout(view.render()),undefined);document.hidden=false;
click(view.render(),labels.viewSecret);let pending=click(view.render(),labels.confirmReveal);const staleSignal=calls.at(-1)[3];window.emit('blur');assert.equal(staleSignal.aborted,true);requests.shift()({ok:true,value:{password:secret}});await pending;assert.equal(readout(view.render()),undefined);
click(view.render(),labels.viewSecret);pending=click(view.render(),labels.confirmReveal);requests.shift()({ok:false,error:{message:secret}});await pending;assert.ok(!JSON.stringify(view.render()).includes(secret));
await shown(view);view.props={...view.props,busy:true};view.render();assert.equal(readout(view.render()),undefined);assert.equal(timers.size,0);
view.unmount();assert.equal(window.listenerCount(),0);assert.equal(document.listenerCount(),0);
const late=makeView();click(late.render(),labels.viewSecret);pending=click(late.render(),labels.confirmReveal);const lateSignal=calls.at(-1)[3];late.unmount();assert.equal(lateSignal.aborted,true);requests.shift()({ok:true,value:{password:secret}});await pending;assert.equal(timers.size,0);assert.equal(late.render(),null);
const duringSave=makeView();click(duringSave.render(),labels.viewSecret);pending=click(duringSave.render(),labels.confirmReveal);const busySignal=calls.at(-1)[3];duringSave.props={...duringSave.props,busy:true};duringSave.render();assert.equal(busySignal.aborted,true);requests.shift()({ok:true,value:{password:secret}});await pending;assert.equal(readout(duringSave.render()),undefined);duringSave.unmount();
const overlap=makeView();click(overlap.render(),labels.viewSecret);const oldPending=click(overlap.render(),labels.confirmReveal),oldResolve=requests.shift();window.emit('blur');click(overlap.render(),labels.viewSecret);const newPending=click(overlap.render(),labels.confirmReveal),newResolve=requests.shift();oldResolve({ok:true,value:{password:'STALE-SYNTHETIC'}});await oldPending;assert.equal(readout(overlap.render()),undefined);newResolve({ok:true,value:{password:secret}});await newPending;assert.equal(readout(overlap.render()).props.value,secret);overlap.unmount();assert.equal(timers.size,0);
root.slots[1]={...root.slots[1],host:'different.example.test'};assert.ok(!nodes(root.render()).some(n=>n.type===componentNode.type));root.slots[1]={...root.slots[1],host:sample.host};root.slots[2]='NEW-SYNTHETIC-PASSWORD';assert.ok(!nodes(root.render()).some(n=>n.type===componentNode.type));
console.log('PASS: explicit confirmation, read-only view, no replacement-field fill, auto-hide, manual hide, blur/visibility cleanup, abort and stale-response rejection, safe error UI, save-state cleanup, unmount cleanup and changed-target/new-password suppression.');
