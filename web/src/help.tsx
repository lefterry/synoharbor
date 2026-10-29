import React,{useId,useRef,useState} from 'react';
import {createPortal} from 'react-dom';

export const syncHelp='Read the current certificates, proxy hosts and SSL assignments from DSM now. Changes and deletions made in DSM update these lists. This check also runs every 30 seconds. It does not issue certificates or edit Cloudflare DNS records.';
export const help:Record<string,string>={
 'Domain or wildcard':'The public DNS name covered by this certificate. A wildcard such as *.syno.example.net covers one subdomain level, but does not cover syno.example.net itself.',
 'ACME email':"Let's Encrypt uses this address for your ACME account. It is not your DSM login.",
 'Key type':'ECDSA uses smaller keys. RSA 4096 provides compatibility with older clients. Each profile keeps its own private key.',
 'Cloudflare credential':'Select the saved token used to create and remove temporary DNS-01 challenge records. Your permanent DNS records stay unchanged.',
 'Automatic renewal':'SynoHarbor checks this certificate independently and renews it before expiry. The package must be running for renewal and deployment.',
 "Use Let's Encrypt staging (test only)":"Tests the issuance flow using Let's Encrypt staging. Browsers do not trust staging certificates. Use a production profile for a real service.",
 'Create a proxy host with this certificate':'Also create a native DSM reverse proxy and assign this certificate to it, in the same workflow.',
 'Hostname':'The address you open in your browser. Its DNS record should point to this NAS, and the selected certificate must cover this name.',
 'Target protocol':'The protocol spoken by the actual service behind the proxy. The browser-facing connection can still use HTTPS when the service uses HTTP.',
 'Target IP or hostname':'The real service address. 127.0.0.1 refers to this Synology NAS. For a service on another machine, enter its LAN IP or hostname.',
 'Target port':'The port on which the actual service listens, such as 32400 for Plex. This is different from the public HTTPS port 443.',
 'WebSockets support':'Allows long-lived connections used by live dashboards, notifications and many web apps.',
 'Enable proxy host':'Disabling removes its native DSM route while retaining the saved configuration and certificate. Certificate renewal is controlled separately.',
 'Certificate':'Choose a deployed production certificate covering this hostname. Certificates are managed separately and can be shared by compatible hosts.',
 'Force SSL':'Creates an HTTP-to-HTTPS redirect for this hostname after HTTPS has been verified. It redirects to the standard HTTPS address, without exposing the service port.',
 'HSTS':'Tells browsers to remember that this hostname must use HTTPS. Enable after testing a valid certificate; browsers keep the policy even if the app is later removed.',
 'HSTS include subdomains':'Extends HSTS to names below this hostname. Enable only when every affected subdomain supports valid HTTPS.',
 'Access list':'Optional IP restrictions and Basic Auth before a request reaches your service. This does not replace the service’s own user accounts.',
 'Cache Assets':'Caches static assets such as images, CSS and JavaScript. Requests containing cookies or Authorization bypass the cache. A proxy_buffering off snippet disables caching for that location.',
 'Block Common Exploits':'Blocks common sensitive file paths and suspicious URL patterns. It is an extra filter, not a substitute for updating your service.',
 'Connect timeout (s)':'Maximum wait while establishing a connection to the service.',
 'Read timeout (s)':'Maximum time between reads from the service. Increase for slow responses or long-lived connections.',
 'Send timeout (s)':'Maximum time between writes while forwarding a request to the service.',
 'Body limit (MB; 0 unlimited)':'Maximum upload/request size accepted by this proxy. Zero disables this size limit.',
 'Location path':'A URL prefix that uses a different target, such as /api. Other paths keep the main service target.',
 'Verify upstream certificate':'Checks the certificate of the HTTPS service behind the proxy. For a self-signed service, supply its trusted certificate instead of turning verification off.',
 'Enable HTTP/2 globally in DSM':'This changes DSM’s native global web setting for the NAS, including services outside SynoHarbor. It is not a per-host setting.',
 'Pass Authorization header to upstream':'Forwards the client’s Authorization header to the service. Leave off when Basic Auth credentials should be consumed only by the proxy.',
 'When IP rules and Basic Auth are both configured':'All requires both an allowed IP and a valid password. Any accepts either condition. If only one method is configured, that method applies.',
 'HTTPS management port':'The HTTPS port configured in DSM Login Portal, usually 5001. SynoHarbor uses it to connect to this NAS internally; it is separate from the proxy listener ports.',
 'Appearance':'System follows your device’s light/dark preference. Light and Dark override it for SynoHarbor.'
};
export function Info({text,label='this setting'}:{text:string;label?:string}){
 const id=useId(),timer=useRef<ReturnType<typeof setTimeout>|null>(null),[pos,setPos]=useState<{top:number;left:number}|null>(null);
 const close=()=>{timer.current=setTimeout(()=>setPos(null),140)};
 const keep=()=>{if(timer.current)clearTimeout(timer.current)};
 return <span className="help"><button type="button" className="help-button" aria-label={'Information about '+label} aria-describedby={pos?id:undefined} onMouseEnter={e=>{keep();const r=e.currentTarget.getBoundingClientRect();setPos({top:r.bottom+7,left:Math.max(8,Math.min(r.left,window.innerWidth-330))})}} onMouseLeave={close} onFocus={e=>{keep();const r=e.currentTarget.getBoundingClientRect();setPos({top:r.bottom+7,left:Math.max(8,Math.min(r.left,window.innerWidth-330))})}} onBlur={close} onClick={e=>{e.preventDefault();e.stopPropagation();if(!pos){const r=e.currentTarget.getBoundingClientRect();setPos({top:r.bottom+7,left:Math.max(8,Math.min(r.left,window.innerWidth-330))})}}} onKeyDown={e=>{if(e.key==='Escape'&&pos){e.preventDefault();e.stopPropagation();setPos(null)}}}>i</button>{pos&&createPortal(<span id={id} role="tooltip" className="help-tooltip" style={pos} onMouseEnter={keep} onMouseLeave={close}>{text}</span>,document.body)}</span>
}

export function Field({label,children,hint}:{label:string;children:React.ReactNode;hint?:string}){return <label className="field"><span>{label}{(hint||help[label])&&<Info label={label} text={hint||help[label]}/>}</span>{children}{hint&&<small>{hint}</small>}</label>}
