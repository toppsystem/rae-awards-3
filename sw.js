const C="rae3-v1";
self.addEventListener("install",()=>self.skipWaiting());
self.addEventListener("activate",e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==C).map(x=>caches.delete(x)))).then(()=>self.clients.claim())));
self.addEventListener("fetch",e=>{const r=e.request,u=new URL(r.url);
 if(r.method!=="GET"||u.pathname.startsWith("/api/"))return;
 if(!(u.origin===location.origin||["cdnjs.cloudflare.com","fonts.gstatic.com","fonts.googleapis.com"].includes(u.hostname)))return;
 e.respondWith(fetch(r).then(res=>{if(res.ok||res.type==="opaque"){const c=res.clone();caches.open(C).then(x=>x.put(r,c))}return res}).catch(()=>caches.match(r).then(m=>m||(r.mode==="navigate"?caches.match("/"):Response.error()))))});
