import {build} from 'esbuild';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const temp=await mkdtemp(join(tmpdir(),'synoharbor-api-'));
try{
 const file=join(temp,'api.cjs');await build({entryPoints:['src/api.ts'],bundle:true,platform:'node',format:'cjs',outfile:file});const source=await readFile(file,'utf8');
 for(const mode of ['dsm','standalone','anonymous']){
  const requests=[];let native=false;
  const context={module:{exports:{}},exports:{},fetch:async(url,options)=>{
   requests.push({url,options});
   if(url.startsWith('/webapi/')){if(mode==='dsm'){native=true;return {status:200,json:async()=>({success:true,data:{synotoken:'native-token'}})}}throw Error('Not exposed')}
   if(url.endsWith('session')){if(mode==='anonymous'||(mode==='dsm'&&!native))return {status:401,json:async()=>({success:false,error:'sign in'})};return {status:200,json:async()=>({success:true,data:{csrfToken:'package-token',authMode:mode,user:'admin'}})}}
   assert.equal(options.headers['X-SynoHarbor-CSRF'],'package-token');
   assert.equal(options.headers['X-SYNO-TOKEN'],mode==='dsm'?'native-token':undefined);
   return {status:200,json:async()=>({success:true,data:{ok:true}})};
  }};
  vm.runInNewContext(source,context);
  if(mode==='anonymous'){await assert.rejects(()=>context.module.exports.api('overview'),e=>e instanceof context.module.exports.SignInRequired);continue}
  await context.module.exports.api('overview');await context.module.exports.api('proxies','POST',{hostname:'one.example.net'});
  assert.equal(context.module.exports.browserIdentity().authMode,mode);
  assert.equal(requests.at(-1).options.headers['Content-Type'],'application/json');
  if(mode==='standalone')assert.equal(requests.some(r=>r.url.startsWith('/webapi/')),false);
 }
 process.stdout.write('Embedded native session, standalone opaque session, CSRF and anonymous denial passed.\n');
}finally{await rm(temp,{recursive:true,force:true})}
