import {build} from 'esbuild';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const temp=await mkdtemp(join(tmpdir(),'synoharbor-api-'));
try{
 const file=join(temp,'api.cjs');await build({entryPoints:['src/api.ts'],bundle:true,platform:'node',format:'cjs',outfile:file});
 const requests=[];const context={module:{exports:{}},exports:{},fetch:async(url,options)=>{
  requests.push({url,options});
  if(url.startsWith('/webapi/'))return {status:200,json:async()=>({success:true,data:{synotoken:'native-session-token'}})};
  assert.equal(options.headers['X-SYNO-TOKEN'],'native-session-token');
  if(url.endsWith('session'))return {status:200,json:async()=>({success:true,data:{csrfToken:'package-session-token'}})};
  assert.equal(options.headers['X-SynoHarbor-CSRF'],'package-session-token');
  return {status:200,json:async()=>({success:true,data:{ok:true}})};
 }};
 vm.runInNewContext(await readFile(file,'utf8'),context);
 await context.module.exports.api('overview');
 await context.module.exports.api('proxies','POST',{hostname:'one.example.net'});
 assert.equal(requests.length,4);assert.equal(requests[3].options.headers['Content-Type'],'application/json');assert.equal(JSON.parse(requests[3].options.body).hostname,'one.example.net');
 process.stdout.write('Native session token → package CSRF → protected reads/writes passed.\n');
}finally{await rm(temp,{recursive:true,force:true})}
