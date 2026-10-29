let csrf='',nativeToken='';
let bootstrapPromise:Promise<void>|null=null;
let identity={user:'',authMode:''};
export class SignInRequired extends Error{}
export function browserIdentity(){return identity}
function reset(){csrf='';nativeToken='';identity={user:'',authMode:''}}
async function bootstrap(){
 if(csrf)return;
 if(!bootstrapPromise)bootstrapPromise=(async()=>{
  const read=async()=>{const r=await fetch('./api.cgi?route=session',{credentials:'same-origin',cache:'no-store',headers:nativeToken?{'X-SYNO-TOKEN':nativeToken}:{}});return {r,b:await r.json()}};
  let {r,b}=await read();
  if(!b.success&&(r.status===401||r.status===403)){
   // Embedded DSM can supply a native cookie. Standalone has its own opaque
   // cookie and never exposes the DSM token endpoint or a worker credential.
   try{const n=await fetch('/webapi/auth.cgi?api=SYNO.API.Auth&version=6&method=token',{credentials:'same-origin',cache:'no-store'});const v=await n.json();if(v.success&&v.data?.synotoken){nativeToken=v.data.synotoken;({r,b}=await read())}}catch{/* standalone route intentionally has no /webapi */}
  }
  if(!b.success){if(r.status===401||r.status===403){reset();throw new SignInRequired('Sign in with a DSM administrator account.')}throw Error(b.error||'Connection unavailable')}
  csrf=b.data.csrfToken;identity={user:b.data.user,authMode:b.data.authMode};
 })().finally(()=>{bootstrapPromise=null});
 return bootstrapPromise;
}
export async function signIn(account:string,password:string,otp:string){
 const r=await fetch('./signin.cgi',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify({account,password,otp})});
 const b=await r.json();if(!b.success)throw Error(b.error||'DSM sign-in failed');reset();await bootstrap();
}
export async function signOut(){await api('signout','POST');reset()}
export async function api<T=any>(route:string,method='GET',body?:unknown):Promise<T>{
 await bootstrap();
 const r=await fetch('./api.cgi?route='+encodeURIComponent(route),{method,credentials:'same-origin',cache:'no-store',headers:{...(nativeToken?{'X-SYNO-TOKEN':nativeToken}:{}),'X-SynoHarbor-CSRF':csrf,...(method!=='GET'?{'Content-Type':'application/json'}:{})},body:method==='GET'?undefined:JSON.stringify(body||{})});
 const b=await r.json();
 if(r.status===401){reset();throw new SignInRequired(b.error||'Session expired. Sign in again.')}
 if(r.status===403){reset()}
 if(!b.success)throw Error(b.error||'Request failed');return b.data;
}
