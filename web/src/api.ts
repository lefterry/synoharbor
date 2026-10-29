let csrf='',nativeToken='';
let nativePromise:Promise<void>|null=null;
async function nativeSession(){
 if(nativeToken)return;
 if(!nativePromise)nativePromise=(async()=>{const r=await fetch('/webapi/auth.cgi?api=SYNO.API.Auth&version=6&method=token',{credentials:'same-origin',cache:'no-store'});const b=await r.json();if(!b.success||!b.data?.synotoken)throw Error('DSM session expired. Sign in to DSM and reopen SynoHarbor.');nativeToken=b.data.synotoken;})().finally(()=>{nativePromise=null});
 return nativePromise;
}

export async function api<T=any>(route:string,method='GET',body?:unknown):Promise<T>{
 await nativeSession();
 if(!csrf){const r=await fetch('./api.cgi?route=session',{credentials:'same-origin',cache:'no-store',headers:{'X-SYNO-TOKEN':nativeToken}});const b=await r.json();if(!b.success){if(r.status===401||r.status===403)nativeToken='';throw Error(b.error||'Open SynoHarbor from an active DSM administrator session.');}csrf=b.data.csrfToken;}
 const r=await fetch('./api.cgi?route='+encodeURIComponent(route),{method,credentials:'same-origin',cache:'no-store',headers:{'X-SYNO-TOKEN':nativeToken,'X-SynoHarbor-CSRF':csrf,...(method!=='GET'?{'Content-Type':'application/json'}:{})},body:method==='GET'?undefined:JSON.stringify(body||{})});
 if(r.status===401||r.status===403){csrf='';nativeToken='';}const b=await r.json();if(!b.success)throw Error(b.error||'Request failed');return b.data;
}
