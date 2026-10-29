let csrf='';
export async function api<T=any>(route:string,method='GET',body?:unknown):Promise<T>{
 if(!csrf){const r=await fetch('./api.cgi?route=session',{credentials:'same-origin',cache:'no-store'});const b=await r.json();if(!b.success)throw Error(b.error||'Open SynoHarbor from an active DSM administrator session.');csrf=b.data.csrfToken;}
 const r=await fetch('./api.cgi?route='+encodeURIComponent(route),{method,credentials:'same-origin',cache:'no-store',headers:{'X-SynoHarbor-CSRF':csrf,...(method!=='GET'?{'Content-Type':'application/json'}:{})},body:method==='GET'?undefined:JSON.stringify(body||{})});
 if(r.status===401||r.status===403)csrf='';const b=await r.json();if(!b.success)throw Error(b.error||'Request failed');return b.data;
}
