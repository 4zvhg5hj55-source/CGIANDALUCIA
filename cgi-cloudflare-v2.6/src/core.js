// CGI · Andalucía RP — lógica del servidor (uso exclusivo del servidor de rol Andalucía RP, no oficial)
// Versión para Cloudflare Workers + Durable Object (SQLite): los datos persisten aunque el servidor se reinicie.
import crypto from 'node:crypto';
import { makeApp } from './mini-express.js';
import { Store } from './store.js';

export function createCore(sql, env = {}) {
const C = crypto;
const R={Aspirante:0.5,Alumno:1,Analista:2,Coordinador:3,'Secretario General':4,'Comisario General':5,'Facciones Legales':6,DAO:6,'Co-Desarrollador':7,Desarrollador:7,UCO:0,UAIL:0,FGE:0};
// Títulos especiales (DAO, Co-Desarrollador, Desarrollador): conservan su poder y ADEMÁS pueden llevar un rango CGI (u.rank),
// salir en las placas y llevar/estar en investigaciones como un agente más. Jerarquía: Desarrollador > FL > Co-Desarrollador > DAO.
// Desarrollador y Co-Desarrollador tienen "modo desarrollador": solo con él activado tienen poder total; si no, solo el de su rango CGI.
const SP=['DAO','Co-Desarrollador','Desarrollador'],DEVM=['Co-Desarrollador','Desarrollador'],RANKS=['Alumno','Analista','Coordinador','Secretario General','Comisario General'];
const rk=u=>SP.includes(u.role)?(RANKS.includes(u.rank)?R[u.rank]:0):R[u.role];
const effLv=(u,dm)=>DEVM.includes(u.role)?(dm?7:(rk(u)||1)):u.role==='DAO'?6:R[u.role];
const lvOf=u=>u.lv??R[u.role]; // nivel efectivo del usuario que hace la petición (lo fija auth)
const store = new Store(sql);
const D = store.load();
const save = () => store.flush(D, false), saveAll = () => store.flush(D, true);
// Migración de datos antiguos (idempotente, no borra nada; mantiene n.cls como espejo para poder volver a la versión anterior sin abrir notas): notas "cls" -> niveles 1-3 y autor por id; informes -> nivel 3 (como se comportaban hasta ahora).
const migrate=()=>{let ch=false;
for(const n of D.notes){if(n.lvl==null){n.lvl=(n.cls==null||n.cls==0)?1:3;if(n.cls==2)n.minRank=4;ch=true}
{const lc=n.minRank?2:n.lvl==1?0:1;if(n.cls!==lc){n.cls=lc;ch=true}}
if(n.byId===undefined){const a=D.users.find(u=>u.user===n.by);n.byId=a?a.id:null;ch=true}
if(!Array.isArray(n.shared)){n.shared=[];ch=true}}
for(const r of D.reports){if(r.lvl==null){r.lvl=3;ch=true}if(r.byId===undefined){r.byId=r.by;ch=true}if(!Array.isArray(r.shared)){r.shared=[];ch=true}}
for(const u of D.users)if('pe' in u){delete u.pe;ch=true} // se eliminan las contraseñas cifradas recuperables de versiones anteriores
if(ch)store.flush(D,true)};migrate();
// Sesiones (persistentes: no se pierden cuando el servidor se "duerme")
const S = {
  m: new Map(store.loadSess()),
  get(k) { return this.m.get(k); },
  set(k, v) { v.pt = Date.now(); this.m.set(k, v); store.putSess(k, { id: v.id, t: v.t, dm: !!v.dm, at: v.at, ua: v.ua, ip: v.ip }); },
  delete(k) { if (this.m.delete(k)) store.delSess(k); },
  touch(k, v) { if (Date.now() - (v.pt || 0) > 6e4) { v.pt = Date.now(); store.putSess(k, { id: v.id, t: v.t, dm: !!v.dm, at: v.at, ua: v.ua, ip: v.ip }); } },
};
const skey = (tk) => C.createHash('sha1').update(tk).digest('hex').slice(0, 12);
const killSess = (uid, except) => { let n = 0; for (const [k, v] of [...S.m]) if (v.id == uid && k !== except) { S.delete(k); n++; } return n; };
const hash=(p,s=C.randomBytes(16).toString('hex'))=>({s,h:C.pbkdf2Sync(p,s,30000,32,'sha256').toString('hex')});
const chk=(p,u)=>{const a=Buffer.from(C.pbkdf2Sync(p,u.s,30000,32,'sha256').toString('hex')),b=Buffer.from(u.h);return a.length==b.length&&C.timingSafeEqual(a,b)};
// Clave de cifrado de contraseñas recuperables: variable CGI_KEY o, si no existe, una clave aleatoria guardada en la base de datos
let K;
if(env.CGI_KEY)K=C.createHash('sha256').update(String(env.CGI_KEY)).digest();
else{let kx=store.getSecret('key');if(!kx){kx=C.randomBytes(32).toString('hex');store.putSecret('key',kx)}K=Buffer.from(kx,'hex')}
// Clave del servidor (secret.key en la base de datos, o la variable CGI_KEY). Ya NO se usa para contraseñas (no hay contraseñas recuperables):
// solo sirve para generar los códigos que sustituyen a las IP reales en logs y sesiones.

const setPw=(u,p)=>{Object.assign(u,hash(p));delete u.pe};
// Cuenta de Desarrollador inicial: se crea si no existe. Para restablecerla (si te quedas sin acceso) pon DEV_RESET = "1" en wrangler.jsonc, despliega y quítalo después.
const DEV_USER='dev',DEFAULT_PASS='CGI-Dev#2026!Atlas',DEV_PASS=env.DEV_PASS?String(env.DEV_PASS):DEFAULT_PASS;
// Mejor: define el secreto DEV_PASS (npx wrangler secret put DEV_PASS) antes del primer despliegue. Si la cuenta dev sigue con la contraseña del LEEME, se le obliga a cambiarla al entrar (mustChange).
const ensureDev=()=>{let d=D.users.find(u=>u.user.toLowerCase()===DEV_USER);
if(!d){d={id:++D.seq.u,user:DEV_USER,discord:'',role:'Desarrollador',name:'Desarrollador CGI',plate:'000',inv:[]};D.users.push(d);setPw(d,DEV_PASS);d.mustChange=DEV_PASS===DEFAULT_PASS;saveAll()}
else if(env.DEV_RESET==='1'){setPw(d,DEV_PASS);d.role='Desarrollador';d.susp=false;d.mustChange=DEV_PASS===DEFAULT_PASS;saveAll()}
else if(d.mustChange===undefined){d.mustChange=chk(DEFAULT_PASS,d);saveAll()}};
ensureDev();

const HOOK=/^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//;
// Avisos al canal de Discord (webhook): solo si el Desarrollador ha configurado la URL
const hook=(a,d,u)=>{const h=D.settings.hook;if(!h||!HOOK.test(h)||typeof fetch!='function')return;fetch(h,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({embeds:[{title:String(a).slice(0,200),description:String(d||'—').slice(0,1500),color:/FALLIDO|BLOQUEADO|SUSPEND|ELIMINAD|RESTAURAD/i.test(a)?0xc8102e:/NIVEL 3|Acceso de|Modo desarrollador|Inactividad|Sospecha/i.test(a)?0xe8832a:0x0a3a82,footer:{text:u?`${u.name} · ${u.role}${u.plate?' · '+u.plate:''}`:'Sin identificar'},timestamp:new Date().toISOString()}]})}).catch(()=>{})};
const FL=new Map(),ip=r=>String(r.headers['cf-connecting-ip']||r.headers['x-forwarded-for']||(r.socket&&r.socket.remoteAddress)||'').split(',')[0].trim();
// Las IP reales NUNCA se guardan: en logs y sesiones solo queda un código (HMAC con la clave del servidor). Sirve para reconocer actividad desde la misma red, pero no permite recuperar la IP.
const IPX=/^IP-[0-9A-F]{10}$/,ipx=v=>{v=String(v||'').trim();return !v?'':IPX.test(v)?v:'IP-'+C.createHmac('sha256',K).update('ip|'+v).digest('hex').slice(0,10).toUpperCase()};
const pub=u=>({id:u.id,user:u.user,discord:u.discord,role:u.role,rank:SP.includes(u.role)?(u.rank||''):'',name:u.name,plate:u.plate,inv:u.inv||[],susp:!!u.susp});
const meOf=(u,dm)=>({...pub(u),dm:!!dm,lv:effLv(u,dm),canDev:DEVM.includes(u.role),mustChange:!!u.mustChange});
const nm=id=>(D.users.find(u=>u.id==id)||{name:'(eliminado)'}).name;
const staff=u=>{const r=rk(u);return r>=1&&r<6};
const L=(q,type,act,det,inv)=>{const u=q.u;D.logs.push({id:++D.seq.l,ts:new Date().toISOString(),type,act,det:det||'',inv:inv||null,user:u?u.user:(q.lu||'—'),name:u?u.name:'',role:u?u.role:'',plate:u?u.plate:'',ip:ipx(ip(q))});if(/FALLIDO|BLOQUEADO|SUSPEND|ELIMINAD|creada|creado|enviado|asociad[oa]|Cambio de mando|Ajustes|Copia|reactivada|Modo desarrollador|Acceso de|RESTAURAD|Punto de restauración|Datos de perfiles|Sospecha recibida/i.test(act))hook(act,det,u);save()};
const inInv=(i,u)=>i.lead==u.id||i.team.includes(u.id)||(R[u.role]===0&&(u.inv||[]).includes(i.id)),vis=(i,u)=>inInv(i,u)||lvOf(u)>=3; // Coordinador o superior ve TODAS las investigaciones
const mg=(i,u)=>i.lead==u.id||lvOf(u)>=3; // ...y las gestiona (editar, equipo, fases, datos). Borrar una investigación: solo Comisario General o superior
const ed=(i,u)=>mg(i,u)||i.team.includes(u.id),edI=(i,u)=>i.lead==u.id||lvOf(u)>=3;
// Niveles de notas e informes: 1 = todos los miembros (incl. alumnos) · 2 = Analista o superior · 3 = Coordinador o superior.
// Además lo ve: su autor, quien un Coordinador+ haya autorizado (d.shared), quien pueda ver la investigación asociada (informes) y FL/DAO/Desarrollador.
// d.minRank solo existe en notas antiguas "Secreto" (Secretario General o superior): se mantiene para no abrirlas a más gente.
const own=(d,u)=>d.byId!=null&&d.byId==u.id;
const dOk=(d,u)=>{const l=lvOf(u);return l>=6||own(d,u)||(d.shared||[]).includes(u.id)||!!(d.inv&&D.invs.some(i=>i.id==d.inv&&inInv(i,u)))||(l>=1&&l>=Math.max(d.lvl||3,d.minRank||0))};
const lcls=n=>n.minRank?2:n.lvl==1?0:1,canR=dOk,nOk=dOk,lvlIn=v=>[1,2,3].includes(+v)?+v:null,okIds=a=>[...new Set((a||[]).map(Number))].filter(x=>D.users.some(u=>u.id==x));
// Historial de versiones: antes de cada edición se guarda lo anterior (máx. 30). Solo lo ven quienes pueden editar.
// Cada versión guardada recuerda quién la escribió y cuándo (by/ts) y quién la sustituyó y cuándo (repBy/repTs).
const HMAX=30,pushH=(o,snap,q)=>{const now=new Date().toISOString();(o.hist||(o.hist=[])).push({ts:o.vTs||o.ts||null,by:o.vBy||String(o.byName||o.by||'').replace(/ \(.*\)$/,''),repBy:q.u.name,repTs:now,...snap});o.vBy=q.u.name;o.vTs=now;if(o.hist.length>HMAX)o.hist.splice(0,o.hist.length-HMAX)};
// Solo el rol Desarrollador puede gestionar cuentas Desarrollador (así nadie puede dejar fuera al dueño de la web)
const can=(q,role)=>R[role]!==undefined&&(R[role]>=6?q.lv>=7&&(role!=='Desarrollador'||q.u.role==='Desarrollador'):q.lv>=5);
// Convierte a código las IP reales que aún hubiera en logs y sesiones antiguas (se ejecuta al arrancar y tras restaurar copias)
const migrateIps=()=>{let n=0;for(const l of D.logs)if(l.ip&&!IPX.test(l.ip)){l.ip=ipx(l.ip);store._write('logs',String(l.id),JSON.stringify(l));n++}
for(const[k,v]of S.m)if(v.ip&&!IPX.test(v.ip)){v.ip=ipx(v.ip);store.putSess(k,{id:v.id,t:v.t,dm:!!v.dm,at:v.at,ua:v.ua,ip:v.ip})}return n};migrateIps();
// ---------- Puntos de restauración (copias dentro de la propia base de datos) ----------
sql.exec('CREATE TABLE IF NOT EXISTS snaps(sid TEXT NOT NULL, coll TEXT NOT NULL, id TEXT NOT NULL, part INTEGER NOT NULL, v TEXT NOT NULL, PRIMARY KEY(sid,coll,id,part))');
sql.exec('CREATE TABLE IF NOT EXISTS snapmeta(sid TEXT PRIMARY KEY, ts TEXT NOT NULL, kind TEXT NOT NULL, note TEXT, bytes INTEGER, lseq INTEGER)');
const SNAP_KEEP={auto:7,manual:6,pre:4},DATA="coll NOT IN ('sess','secret')";
const pruneSnaps=()=>{for(const[k,n]of Object.entries(SNAP_KEEP))for(const r of sql.exec('SELECT sid FROM snapmeta WHERE kind=? ORDER BY ts DESC',k).toArray().slice(n)){sql.exec('DELETE FROM snaps WHERE sid=?',r.sid);sql.exec('DELETE FROM snapmeta WHERE sid=?',r.sid)}};
const snapNow=(kind,note)=>{saveAll();const ts=new Date().toISOString(),sid=ts.replace(/\D/g,'').slice(0,14)+'-'+C.randomBytes(2).toString('hex');
sql.exec(`INSERT INTO snaps(sid,coll,id,part,v) SELECT ?,coll,id,part,v FROM items WHERE ${DATA}`,sid);
const b=sql.exec('SELECT COALESCE(SUM(LENGTH(v)),0) AS b FROM snaps WHERE sid=?',sid).toArray()[0].b;
sql.exec('INSERT INTO snapmeta(sid,ts,kind,note,bytes,lseq) VALUES(?,?,?,?,?,?)',sid,ts,kind,note||'',b,D.seq.l);pruneSnaps();return sid};
// Copia diaria automática (la dispara la alarma del Durable Object): solo si ha habido actividad desde la última
const autoSnap=()=>{const last=sql.exec("SELECT lseq FROM snapmeta WHERE kind='auto' ORDER BY ts DESC LIMIT 1").toArray()[0];return last&&last.lseq===D.seq.l?null:snapNow('auto','Copia automática diaria')};
const reload=()=>{const f=store.load();for(const k of Object.keys(D))delete D[k];Object.assign(D,f);migrate();migrateIps();ensureDev()};
const restoreSnap=sid=>{if(!sql.exec('SELECT sid FROM snapmeta WHERE sid=?',sid).toArray().length)return false;snapNow('pre','Antes de restaurar el punto '+sid);
sql.exec(`DELETE FROM items WHERE ${DATA}`);sql.exec('INSERT INTO items(coll,id,part,v) SELECT coll,id,part,v FROM snaps WHERE sid=?',sid);reload();return true};
const badBackup=b=>{if(!b||typeof b!=='object')return 'El archivo no es una copia válida';
for(const k of['users','notes','reports','invs'])if(!Array.isArray(b[k]))return `Falta «${k}» en la copia`;
if(!b.users.every(u=>u&&u.user&&u.s&&u.h&&u.id!=null&&Object.hasOwn(R,u.role)))return 'Hay perfiles no válidos en la copia';
if(!b.invs.every(i=>i&&Array.isArray(i.team)&&Array.isArray(i.info)&&Array.isArray(i.people))||!b.notes.every(n=>n&&Array.isArray(n.files)))return 'Hay investigaciones o notas con un formato no válido';
if(!b.users.some(u=>u.role==='Desarrollador'&&!u.susp))return 'La copia no contiene ninguna cuenta Desarrollador activa (te quedarías sin acceso)';return ''};
const maxId=a=>a.reduce((m,x)=>Math.max(m,+x.id||0),0);
const applyBackup=b=>{snapNow('pre','Antes de restaurar desde archivo');sql.exec(`DELETE FROM items WHERE ${DATA}`);store.cache={};store.logN=0;
const tps=Array.isArray(b.tips)?b.tips:[],ans=Array.isArray(b.anotes)?b.anotes:[],sb=Array.isArray(b.shifts)?b.shifts:[],tkk=Array.isArray(b.tasks)?b.tasks:[],fi=Array.isArray(b.fichas)?b.fichas:[],lg=Array.isArray(b.logs)?b.logs:[],sq=b.seq&&typeof b.seq==='object'?b.seq:{};
const nd={users:b.users,notes:b.notes,reports:b.reports,invs:b.invs,fichas:fi,logs:lg,shifts:sb,tasks:tkk,tips:tps,anotes:ans,settings:{name:String(b.settings?.name||'Comisaría General de Información').slice(0,60),welcome:String(b.settings?.welcome||'Acceso autorizado').slice(0,100),hook:HOOK.test(b.settings?.hook||'')?b.settings.hook:'',minWeek:b.settings?.minWeek,minMonth:b.settings?.minMonth},
seq:{...sq,u:Math.max(+sq.u||0,maxId(b.users)),n:Math.max(+sq.n||0,maxId(b.notes)),r:Math.max(+sq.r||0,maxId(b.reports)),i:Math.max(+sq.i||0,maxId(b.invs)),l:Math.max(+sq.l||0,maxId(lg)),f:Math.max(+sq.f||0,maxId(fi)),sh:Math.max(+sq.sh||0,maxId(sb)),tk:Math.max(+sq.tk||0,maxId(tkk)),tg:Math.max(+sq.tg||0,tkk.reduce((m,t)=>Math.max(m,+t.gid||0),0)),tp:Math.max(+sq.tp||0,maxId(tps)),an:Math.max(+sq.an||0,maxId(ans))}};
for(const k of Object.keys(D))delete D[k];Object.assign(D,nd);migrate();migrateIps();ensureDev();store.flush(D,true)};
const snapList=()=>sql.exec('SELECT sid,ts,kind,note,bytes FROM snapmeta ORDER BY ts DESC').toArray().map(r=>({...r,counts:Object.fromEntries(sql.exec('SELECT coll,COUNT(DISTINCT id) AS n FROM snaps WHERE sid=? GROUP BY coll',r.sid).toArray().map(x=>[x.coll,x.n]))}));
const storageInfo=()=>({coll:sql.exec(`SELECT coll,COUNT(DISTINCT id) AS n,COALESCE(SUM(LENGTH(v)),0) AS b FROM items WHERE ${DATA} GROUP BY coll`).toArray(),snapBytes:sql.exec('SELECT COALESCE(SUM(LENGTH(v)),0) AS b FROM snaps').toArray()[0].b});
const E=(s,m,c)=>s.status(c||400).json({e:m});

const app=makeApp();
const auth=(min=0)=>(q,s,n)=>{const k=(q.headers.authorization||'').slice(7),ss=S.get(k),u=ss&&Date.now()-ss.t<18e5&&D.users.find(x=>x.id==ss.id&&!x.susp);if(!u){S.delete(k);return E(s,'Sesión no válida',401)}ss.t=Date.now();S.touch(k,ss);q.u=u;q.ss=ss;q.dm=!!ss.dm&&DEVM.includes(u.role);q.lv=effLv(u,q.dm);Object.defineProperty(u,'lv',{value:q.lv,writable:true,configurable:true,enumerable:false});if(u.mustChange&&q.url!=='/api/me'&&q.url!=='/api/logout')return E(s,'Debes cambiar la contraseña inicial antes de continuar',403);
// Un aspirante solo puede usar su cuenta y la zona de notas de aspirantes
if(u.role==='Aspirante'&&!/^\/api\/(me|logout|sessions(\/[^/]+)?|aspirantes\/.+)$/.test(q.url))return E(s,'Tu rango de aspirante solo permite acceder a tus notas de aspirante',403);if(q.lv<min)return E(s,'Sin permisos',403);n()};

// ---------- Sesión ----------
app.post('/api/login',(q,s)=>{const{u,p}=q.body||{},x=D.users.find(a=>a.user.toLowerCase()===String(u||'').toLowerCase()),k=ip(q),f=FL.get(k)||{n:0,t:0},rec=Date.now()-f.t<6e5;q.lu=String(u||'').slice(0,40);
if(f.n>=8&&rec){L(q,'auth','Inicio de sesión BLOQUEADO','Demasiados intentos fallidos desde esta IP');return E(s,'Demasiados intentos. Espera 10 minutos.',429)}
if(!x||!chk(String(p||''),x)){FL.set(k,{n:(rec?f.n:0)+1,t:Date.now()});L(q,'auth','Intento de inicio de sesión FALLIDO',x?'Contraseña incorrecta':'Usuario inexistente');return E(s,'Usuario o contraseña incorrectos',401)}
FL.delete(k);if(x.susp){L(q,'auth','Intento de acceso con cuenta SUSPENDIDA','');return E(s,'Cuenta suspendida. Contacta con el mando.',403)}const tk=C.randomBytes(24).toString('hex');S.set(tk,{id:x.id,t:Date.now(),at:Date.now(),ua:String(q.headers['user-agent']||'').slice(0,200),ip:ipx(k)});q.u=x;L(q,'auth','Inicio de sesión correcto','');s.json({tk,me:meOf(x,false)})});
app.post('/api/logout',auth(),(q,s)=>{L(q,'auth','Cierre de sesión');S.delete(q.headers.authorization.slice(7));s.json({})});
app.get('/api/me',auth(),(q,s)=>s.json(meOf(q.u,q.dm)));
// Modo desarrollador (solo Desarrollador y Co-Desarrollador): activado = poder total; desactivado = solo el de su rango CGI. Se apaga en cada inicio de sesión.
app.put('/api/devmode',auth(),(q,s)=>{if(!DEVM.includes(q.u.role))return E(s,'Sin permisos',403);const on=!!q.body.on;q.ss.dm=on;S.set(q.headers.authorization.slice(7),q.ss);q.dm=on;q.lv=effLv(q.u,on);
L(q,'dev',on?'Modo desarrollador ACTIVADO':'Modo desarrollador desactivado','');s.json(meOf(q.u,on))});
app.put('/api/me',auth(),(q,s)=>{const b=q.body,u=q.u;if(!chk(String(b.cur||''),u)){L(q,'auth','Intento fallido de edición de cuenta propia','Contraseña actual incorrecta');return E(s,'La contraseña actual no es correcta')}
if(u.mustChange&&(!b.pass||String(b.pass).length<8))return E(s,'Elige una nueva contraseña de al menos 8 caracteres');if(b.pass&&String(b.pass)===DEFAULT_PASS)return E(s,'Elige una contraseña distinta de la inicial');if(b.pass&&String(b.pass)===String(b.cur))return E(s,'La nueva contraseña debe ser distinta de la actual');
const ch=[],nu=String(b.user||'').trim();
if(nu&&nu!==u.user){if(D.users.some(x=>x.id!=u.id&&x.user.toLowerCase()==nu.toLowerCase()))return E(s,'Ese usuario ya existe');u.user=nu;ch.push('usuario')}
if(b.pass){if(String(b.pass).length<6)return E(s,'La contraseña debe tener al menos 6 caracteres');setPw(u,String(b.pass));u.mustChange=false;killSess(u.id,q.headers.authorization.slice(7));ch.push('contraseña')}
if(!ch.length)return E(s,'No has cambiado nada');L(q,'usuarios','Edición de cuenta propia','Ha editado: '+ch.join(' y '));saveAll();s.json(meOf(u,q.dm))});
// Ajustes de la web (lectura pública para el login; solo Desarrollador puede cambiarlos)
app.get('/api/settings',(q,s)=>s.json({name:D.settings.name,welcome:D.settings.welcome}));
app.get('/api/settings/hook',auth(7),(q,s)=>s.json({hook:D.settings.hook||''}));
app.get('/api/snaps',auth(5),(q,s)=>s.json({snaps:snapList(),storage:storageInfo(),offsite:{enabled:!!env.BACKUPS,last:D.seq.off||null}}));
app.post('/api/snaps',auth(5),(q,s)=>{const note=String(q.body.note||'').slice(0,100),sid=snapNow('manual',note);L(q,'dev','Punto de restauración creado',`${sid}${note?' · '+note:''}`);s.json({sid})});
app.delete('/api/snaps/:sid',auth(7),(q,s)=>{if(!sql.exec('SELECT sid FROM snapmeta WHERE sid=?',q.params.sid).toArray().length)return E(s,'No existe',404);sql.exec('DELETE FROM snaps WHERE sid=?',q.params.sid);sql.exec('DELETE FROM snapmeta WHERE sid=?',q.params.sid);L(q,'dev','Punto de restauración eliminado',q.params.sid);s.json({})});
app.post('/api/snaps/:sid/restore',auth(7),(q,s)=>{if(!restoreSnap(q.params.sid))return E(s,'No existe ese punto de restauración',404);L(q,'dev','Datos RESTAURADOS desde un punto de restauración',q.params.sid);s.json({})});
app.post('/api/restore',auth(7),(q,s)=>{const e=badBackup(q.body.data);if(e)return E(s,e);applyBackup(q.body.data);L(q,'dev','Datos RESTAURADOS desde un archivo de copia',`${D.users.length} perfiles · ${D.notes.length} notas · ${D.reports.length} informes · ${D.invs.length} investigaciones`);s.json({})});
// Desarrollador: copia COMPLETA. Comisario General / FL: copia «de consulta» sin hashes de contraseñas ni webhook, que además NO se puede importar.
app.get('/api/backup',auth(5),(q,s)=>{const full=q.lv>=7;L(q,'dev','Copia de seguridad descargada',full?'data.json completo':'copia de consulta (sin contraseñas ni webhook; no importable)');
const d=full?D:{...D,users:D.users.map(u=>{const y={...u};delete y.h;delete y.s;return y}),settings:{...D.settings,hook:''}};
s.set({'Content-Type':'application/json','Content-Disposition':`attachment; filename="cgi-${full?'backup':'copia-consulta'}-${new Date().toISOString().slice(0,10)}.json"`}).send(JSON.stringify(d))});
app.put('/api/settings',auth(7),(q,s)=>{const n=String(q.body.name||'').trim().slice(0,60),w=String(q.body.welcome||'').trim().slice(0,100);if(!n)return E(s,'El nombre del portal no puede estar vacío');
const h=String(q.body.hook||'').trim();if(h&&!HOOK.test(h))return E(s,'El webhook debe ser una URL de webhook de Discord');
D.settings={...D.settings,name:n,welcome:w||'Acceso autorizado',hook:h};L(q,'dev','Ajustes de la web modificados',`nombre: ${n} | bienvenida: ${D.settings.welcome} | webhook de Discord: ${h?'configurado':'desactivado'}`);if(h)hook('Webhook conectado','✅ El registro de la CGI enviará avisos a este canal.');saveAll();s.json({name:n,welcome:D.settings.welcome})});
app.get('/api/stats',auth(),(q,s)=>s.json({inv:D.invs.filter(i=>vis(i,q.u)).length,notes:q.lv?D.notes.filter(n=>nOk(n,q.u)).length:0,reports:D.reports.filter(r=>canR(r,q.u)).length,members:D.users.filter(staff).length,tp:D.tasks.filter(t=>t.to==q.u.id&&t.st==='Pendiente').length,tn:q.lv>=1?D.tips.filter(t=>t.st==='Nueva').length:0}));
app.get('/api/dir',auth(1),(q,s)=>s.json(D.users.filter(u=>R[u.role]===0||staff(u)).map(u=>({id:u.id,name:u.name,plate:u.plate,role:SP.includes(u.role)?u.rank:u.role,title:SP.includes(u.role)?u.role:'',discord:u.discord}))));

// ---------- Perfiles ----------
app.get('/api/users',auth(5),(q,s)=>{const dev=q.query.scope=='dev';if(dev&&q.lv<7)return E(s,'Sin permisos',403);s.json(D.users.map(u=>{const x=pub(u);if(q.lv<7)delete x.user;x.limited=R[u.role]>=6&&!can(q,u.role);return x}))}); // x.limited: perfil privilegiado que este usuario solo puede editar en placa, Discord y rango secundario
// Descarga de datos de perfiles (CSV para Excel). Nunca incluye contraseñas; el usuario de acceso solo se incluye en el Panel Desarrollador.
const csv=rows=>'\ufeff'+rows.map(r=>r.map(v=>{v=String(v??'');if(/^[=+\-@\t\r]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"'}).join(',')).join('\r\n');
app.get('/api/users/export',auth(5),(q,s)=>{const dev=q.query.scope=='dev';if(dev&&q.lv<7)return E(s,'Sin permisos',403);const a=D.users;
const rows=[[...(dev?['usuario']:[]),'id','nombre','placa','rango','titulo_especial','rango_cgi_del_titulo','discord','estado','investigaciones_externo'],...a.map(u=>[...(dev?[u.user]:[]),u.id,u.name,u.plate,SP.includes(u.role)?'':u.role,SP.includes(u.role)?u.role:'',SP.includes(u.role)?(u.rank||''):'',u.discord,u.susp?'suspendida':'activa',(u.inv||[]).map(i=>(D.invs.find(x=>x.id==i)||{}).name||i).join(' | ')])];
L(q,dev?'dev':'usuarios','Datos de perfiles descargados',`${a.length} perfil(es) · ${dev?'incluye usuarios de acceso':'sin usuarios ni contraseñas'}`);
s.set({'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="perfiles-cgi.csv"'}).send(csv(rows))});
app.post('/api/users',auth(5),(q,s)=>{const b=q.body;if(!can(q,b.role))return E(s,'No puedes gestionar ese rango',403);
if(!b.user||!b.pass||!b.name)return E(s,'Usuario, contraseña y nombre completo son obligatorios');
if(D.users.some(x=>x.user.toLowerCase()==String(b.user).toLowerCase()))return E(s,'Ese usuario ya existe');
const u={id:++D.seq.u,user:String(b.user).trim(),...hash(String(b.pass)),mustChange:true,ts:new Date().toISOString(),discord:b.discord||'',role:b.role,name:b.name,plate:b.plate||'',inv:R[b.role]===0?(b.inv||[]).map(Number):[],...(SP.includes(b.role)&&RANKS.includes(b.rank)?{rank:b.rank}:{})};
D.users.push(u);L(q,R[u.role]>=6?'dev':'usuarios','Perfil creado',`${u.name} · ${u.role} · placa ${u.plate}`);saveAll();s.json(pub(u))});
app.put('/api/users/:id',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id),b=q.body;if(!u)return E(s,'No existe',404);
// Perfiles privilegiados (FL, DAO, Co-Desarrollador, Desarrollador) editados por un Comisario General o superior SIN poder de Desarrollador:
// solo se pueden editar placa, Discord y el rango CGI secundario (el de la división). Lo demás (nombre, título, usuario, contraseña, suspender, borrar) sigue siendo del Desarrollador.
if(R[u.role]>=6&&!can(q,u.role)){const nr=SP.includes(u.role)&&b.rank!==undefined?(RANKS.includes(b.rank)?b.rank:''):null;if(nr!==null&&nr!==(u.rank||'')&&u.id==q.u.id)return E(s,'No puedes cambiar tu propio rango');
const lc=[],pl=b.plate!==undefined?String(b.plate).slice(0,20):u.plate,dc=b.discord!==undefined?String(b.discord).slice(0,60):u.discord;
if(pl!==u.plate){lc.push(`placa: ${u.plate} → ${pl}`);u.plate=pl}if(dc!==u.discord){lc.push(`discord: ${u.discord} → ${dc}`);u.discord=dc}
if(nr!==null&&nr!==(u.rank||'')){lc.push(`rango CGI: ${u.rank||'sin rango'} → ${nr||'sin rango'}`);if(nr)u.rank=nr;else delete u.rank}
L(q,'dev','Perfil editado',`${u.name}: ${lc.join(' | ')||'sin cambios'}`);saveAll();return s.json(pub(u))}
if(!can(q,u.role)||!can(q,b.role||u.role))return E(s,'No puedes gestionar ese rango',403);
if(u.id==q.u.id&&b.role&&b.role!==u.role)return E(s,'No puedes cambiar tu propio rango');
if(b.user&&q.lv>=7&&b.user.toLowerCase()!=u.user.toLowerCase()&&D.users.some(x=>x.user.toLowerCase()==b.user.toLowerCase()))return E(s,'Ese usuario ya existe');
const ch=[];(q.lv>=7?['user','discord','name','plate','role']:['discord','name','plate','role']).forEach(k=>{if(b[k]!==undefined&&b[k]!==u[k]){ch.push(k=='user'?'usuario modificado':`${k}: ${u[k]} → ${b[k]}`);u[k]=b[k]}});
if(!SP.includes(u.role)){if(u.rank){delete u.rank;ch.push('rango CGI retirado')}}
else if(b.rank!==undefined&&q.lv>=7){const nr=RANKS.includes(b.rank)?b.rank:'';if(nr!==(u.rank||'')){ch.push(`rango CGI: ${u.rank||'sin rango'} → ${nr||'sin rango'}`);if(nr)u.rank=nr;else delete u.rank}}
if(b.pass&&q.lv>=7){setPw(u,String(b.pass));u.mustChange=u.id!==q.u.id;killSess(u.id);ch.push('contraseña modificada')}
if(R[u.role]===0&&b.inv){u.inv=b.inv.map(Number);ch.push('accesos a investigaciones: '+u.inv.join(','))}
L(q,R[u.role]>=6?'dev':'usuarios','Perfil editado',`${u.name}: ${ch.join(' | ')||'sin cambios'}`);saveAll();s.json(pub(u))});
app.put('/api/users/:id/susp',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u)return E(s,'No existe',404);if(!can(q,u.role))return E(s,'No puedes gestionar ese rango',403);if(u.id==q.u.id)return E(s,'No puedes suspenderte a ti mismo');
u.susp=!!q.body.susp;L(q,R[u.role]>=6?'dev':'usuarios',u.susp?'Cuenta SUSPENDIDA':'Cuenta reactivada',`${u.name} · ${u.role}`);saveAll();s.json(pub(u))});
// ---------- Sesiones: ver y cerrar las de otros dispositivos ----------
app.get('/api/sessions',auth(),(q,s)=>{const me=q.headers.authorization.slice(7);s.json([...S.m].filter(([k,v])=>v.id==q.u.id).map(([k,v])=>({sid:skey(k),current:k===me,at:v.at||null,last:v.t,ua:v.ua||'',ip:v.ip||''})).sort((a,b)=>b.last-a.last))});
app.delete('/api/sessions/others',auth(),(q,s)=>{const n=killSess(q.u.id,q.headers.authorization.slice(7));L(q,'auth','Sesiones cerradas',`Ha cerrado ${n} sesión(es) en otros dispositivos`);s.json({n})});
app.delete('/api/sessions/:sid',auth(),(q,s)=>{const me=q.headers.authorization.slice(7),e=[...S.m].find(([k,v])=>v.id==q.u.id&&k!==me&&skey(k)===q.params.sid);if(!e)return E(s,'No existe esa sesión',404);S.delete(e[0]);L(q,'auth','Sesión cerrada','Ha cerrado una sesión de otro dispositivo');s.json({})});
app.delete('/api/users/:id/sessions',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u)return E(s,'No existe',404);if(!can(q,u.role)||u.id==q.u.id)return E(s,'No puedes gestionar las sesiones de ese perfil',403);const n=killSess(u.id);L(q,R[u.role]>=6?'dev':'usuarios','Sesiones de un perfil cerradas',`${u.name}: ${n} sesión(es)`);s.json({n})});
// NADIE puede ver contraseñas (ni el Desarrollador): solo se pueden RESTABLECER. La nueva es provisional y la persona debe cambiarla al entrar.
app.post('/api/users/:id/reset-password',auth(7),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u)return E(s,'No existe',404);if(u.id==q.u.id)return E(s,'Para cambiar tu propia contraseña usa «Mi cuenta»');if(!can(q,u.role))return E(s,'No puedes gestionar ese perfil',403);
const al='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';let p='';for(let i=0;i<12;i++)p+=al[C.randomInt(al.length)];setPw(u,p);u.mustChange=true;const n=killSess(u.id);
L(q,'dev','Contraseña restablecida por el Desarrollador',`Perfil: ${u.name} (${n} sesión(es) cerradas)`);saveAll();s.json({pass:p})});
app.delete('/api/users/:id',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u)return E(s,'No existe',404);
if(!can(q,u.role))return E(s,'No puedes gestionar ese rango',403);if(u.id==q.u.id)return E(s,'No puedes eliminar tu propio perfil');
D.users=D.users.filter(x=>x!==u);D.invs.forEach(i=>{i.team=i.team.filter(x=>x!=u.id)});L(q,R[u.role]>=6?'dev':'usuarios','Perfil eliminado',`${u.name} · ${u.role}`);saveAll();s.json({})});

// ---------- Logs (solo lectura: no existe ninguna ruta para editar o borrar) ----------
const flt=(Q,lv)=>{const{q:t,type,user,inv,from,to}=Q;let a=D.logs.map(l=>lv>=7?l:{...l,user:l.name||'(no identificado)'});
if(type)a=a.filter(l=>l.type==type);if(user)a=a.filter(l=>l.user==user);if(inv)a=a.filter(l=>l.inv==inv);
if(from)a=a.filter(l=>l.ts.slice(0,10)>=from);if(to)a=a.filter(l=>l.ts.slice(0,10)<=to);
if(t){const w=t.toLowerCase();a=a.filter(l=>JSON.stringify(l).toLowerCase().includes(w))}
return a};
app.get('/api/logs',auth(3),(q,s)=>{const a=flt(q.query,q.lv);s.json({total:a.length,rows:a.slice(-500).reverse(),users:[...new Set(flt({},q.lv).map(l=>l.user))],invs:D.invs.map(i=>({id:i.id,name:i.name}))})});
// Exportación CSV (respeta los filtros; las celdas que empiezan por = + - @ se neutralizan)
app.get('/api/logs/export',auth(3),(q,s)=>{const a=flt(q.query,q.lv).slice().reverse(),c=v=>{v=String(v??'');if(/^[=+\-@\t\r]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"'};
const csv=['id,fecha_utc,tipo,usuario,nombre,rango,placa,accion,detalle,ip',...a.map(l=>[l.id,l.ts,l.type,l.user,l.name,l.role,l.plate,l.act,l.det,l.ip].map(c).join(','))].join('\r\n');
L(q,'logs','Logs exportados a CSV',`${a.length} registro(s)`);s.set({'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="logs-cgi.csv"'}).send('\ufeff'+csv)});

// ---------- Notas informativas (niveles 1-3) ----------
const nSum=n=>({id:n.id,num:n.id,when:n.when,event:n.event,byName:n.byName,files:n.files.length,lvl:n.lvl||3,legacy:!!n.minRank,inv:n.inv||null,invName:n.invName||'',edited:(n.hist||[]).length});
app.get('/api/notes',auth(1),(q,s)=>{const w=(q.query.q||'').toLowerCase();s.json(D.notes.filter(n=>nOk(n,q.u)&&(!w||`${n.id} ${n.event} ${n.byName} ${n.invName||''}`.toLowerCase().includes(w))).reverse().map(nSum))});
// Abierta también a externos (UCO/UAIL/FGE) SOLO si la nota está asociada a una investigación a la que tienen acceso (lo decide nOk)
const nEd=(n,u)=>own(n,u)||lvOf(u)>=3;
app.get('/api/notes/:id',auth(),(q,s)=>{const n=D.notes.find(x=>x.id==q.params.id);n&&nOk(n,q.u)?s.json({...n,by:undefined,num:n.id,lvl:n.lvl||3,shared:q.lv>=3?(n.shared||[]):undefined,canEdit:q.lv>=1&&nEd(n,q.u),hist:nEd(n,q.u)?(n.hist||[]).slice().reverse():undefined}):E(s,'No existe',404)});
app.put('/api/notes/:id',auth(1),(q,s)=>{const n=D.notes.find(x=>x.id==q.params.id);if(!n||!nOk(n,q.u))return E(s,'No existe',404);if(!nEd(n,q.u))return E(s,'Solo el autor o un Coordinador o superior puede editar la nota',403);const b=q.body,when=String(b.when||n.when),ev=String(b.event||'').trim().slice(0,6000);if(!ev)return E(s,'El suceso no puede estar vacío');
if(ev===n.event&&when===n.when)return s.json({});pushH(n,{when:n.when,event:n.event},q);n.when=when;n.event=ev;L(q,'notas','Nota informativa EDITADA',`Nº ${n.id} · versión ${n.hist.length+1}`,n.inv);saveAll();s.json({})});
app.post('/api/notes',auth(1),(q,s)=>{const b=q.body;if(!b.when||!b.event)return E(s,'Indica día/hora y suceso');const i=b.inv?D.invs.find(x=>x.id==b.inv):null;if(b.inv&&(!i||!(vis(i,q.u)||q.lv>=3)))return E(s,'Investigación no válida');
const files=(b.files||[]).filter(f=>/^data:image\/(jpeg|png|webp|gif);base64,/.test(f)).slice(0,12);
const n={id:++D.seq.n,lvl:lvlIn(b.lvl)||1,when:b.when,event:String(b.event).slice(0,6000),files,by:q.u.user,byId:q.u.id,byName:`${q.u.name} (${q.u.plate})`,inv:i?i.id:null,invName:i?i.name:'',shared:q.lv>=3?okIds(b.shared).filter(x=>x!=q.u.id):[],ts:new Date().toISOString()};
n.cls=lcls(n);D.notes.push(n);L(q,'notas',n.lvl==3?'Nota informativa creada (NIVEL 3)':'Nota informativa creada',`Nº ${n.id} · Nivel ${n.lvl} · ${files.length} archivo(s)${i?' · investigación '+i.name:''}${n.shared.length?' · acceso especial: '+n.shared.map(nm).join(', '):''}`,n.inv);saveAll();s.json({id:n.id})});
app.put('/api/notes/:id/inv',auth(3),(q,s)=>{const n=D.notes.find(x=>x.id==q.params.id),i=q.body.inv?D.invs.find(x=>x.id==q.body.inv):null;if(!n||!nOk(n,q.u))return E(s,'No existe',404);if(q.body.inv&&!i)return E(s,'Investigación no válida');
const old=n.invName||'ninguna';n.inv=i?i.id:null;n.invName=i?i.name:'';L(q,'notas','Nota asociada a investigación',`Nº ${n.id}: ${old} → ${n.invName||'ninguna'}${i?' (quien pueda ver la investigación ya puede ver la nota)':''}`,n.inv);saveAll();s.json({})});
// Un Coordinador o superior cambia el nivel y/o autoriza a personas concretas aunque su rango no llegue al nivel
app.put('/api/notes/:id/access',auth(3),(q,s)=>{const n=D.notes.find(x=>x.id==q.params.id);if(!n||!nOk(n,q.u))return E(s,'No existe',404);const l=lvlIn(q.body.lvl)||n.lvl||3,sh=okIds(q.body.users).filter(x=>x!=n.byId),was=n.lvl||3;
n.lvl=l;n.shared=sh;delete n.minRank;n.cls=lcls(n);L(q,'notas','Acceso de nota modificado',`Nº ${n.id}: Nivel ${was} → Nivel ${l} · acceso especial: ${sh.map(nm).join(', ')||'nadie'}`,n.inv);saveAll();s.json({})});
app.delete('/api/notes/:id',auth(3),(q,s)=>{const n=D.notes.find(x=>x.id==q.params.id);if(!n||!nOk(n,q.u))return E(s,'No existe',404);
D.notes=D.notes.filter(x=>x!==n);L(q,'notas','Nota informativa ELIMINADA',`Nº ${n.id} de ${n.byName}: ${n.event.slice(0,120)}`,n.inv);saveAll();s.json({})});

// ---------- Base de datos común: personas, bandas y vehículos ----------
const FT=['Persona','Banda','Vehículo'];
const fv=(q,s)=>{const b=q.body;if(!b.name){E(s,'Indica el nombre');return null}if(!FT.includes(b.type)){E(s,'Tipo no válido');return null}
return{type:b.type,name:String(b.name).slice(0,80),alias:String(b.alias||'').slice(0,80),plate:String(b.plate||'').slice(0,20),op:String(b.op||'').slice(0,120),notes:String(b.notes||'').slice(0,1500),files:(b.files||[]).filter(f=>/^data:image\/(jpeg|png|webp|gif);base64,/.test(f)).slice(0,6)}};
app.get('/api/fichas',auth(1),(q,s)=>{const w=(q.query.q||'').toLowerCase(),t=q.query.t;s.json(D.fichas.filter(f=>(!t||f.type==t)&&(!w||`${f.name} ${f.alias} ${f.plate} ${f.op} ${f.notes}`.toLowerCase().includes(w))).reverse().map(f=>({...f,hist:undefined,files:f.files.slice(0,1)})))});
app.get('/api/fichas/:id',auth(1),(q,s)=>{const f=D.fichas.find(x=>x.id==q.params.id);f?s.json({...f,hist:q.lv>=2?(f.hist||[]).slice().reverse():undefined,invs:D.invs.filter(i=>(i.fichas||[]).includes(f.id)&&vis(i,q.u)).map(i=>({id:i.id,name:i.name}))}):E(s,'No existe',404)});
app.post('/api/fichas',auth(2),(q,s)=>{const v=fv(q,s);if(!v)return;const f={id:D.seq.f=(D.seq.f||0)+1,...v,by:q.u.name,ts:new Date().toISOString()};D.fichas.push(f);L(q,'fichas','Ficha creada',`${f.type}: ${f.name}`);saveAll();s.json({id:f.id})});
app.put('/api/fichas/:id',auth(2),(q,s)=>{const f=D.fichas.find(x=>x.id==q.params.id);if(!f)return E(s,'No existe',404);const v=fv(q,s);if(!v)return;if(['type','name','alias','plate','op','notes'].some(k=>v[k]!==f[k]))pushH(f,{type:f.type,name:f.name,alias:f.alias,plate:f.plate,op:f.op,notes:f.notes},q);Object.assign(f,v);L(q,'fichas','Ficha editada',`${f.type}: ${f.name}`);saveAll();s.json({})});
app.delete('/api/fichas/:id',auth(3),(q,s)=>{const f=D.fichas.find(x=>x.id==q.params.id);if(!f)return E(s,'No existe',404);D.fichas=D.fichas.filter(x=>x!==f);D.invs.forEach(i=>{if(i.fichas)i.fichas=i.fichas.filter(x=>x!=f.id)});L(q,'fichas','Ficha ELIMINADA',`${f.type}: ${f.name}`);saveAll();s.json({})});

// ---------- Informes (niveles 1-3) ----------
const rEd=(r,u)=>own(r,u)||lvOf(u)>=3;
const rOut=(r,u)=>({...r,url:undefined,hist:undefined,nHist:rEd(r,u)?(r.hist||[]).length:0,canEdit:rEd(r,u),lvl:r.lvl||3,shared:lvOf(u)>=3?(r.shared||[]):undefined});
app.get('/api/reports',auth(1),(q,s)=>s.json(D.reports.filter(r=>canR(r,q.u)).reverse().map(r=>rOut(r,q.u))));
app.post('/api/reports',auth(1),(q,s)=>{const b=q.body;if(!/^https:\/\/(docs|drive)\.google\.com\//.test(b.url||''))return E(s,'Pega un enlace válido de Google Docs');
if(!b.context)return E(s,'Escribe el contexto del informe');const i=b.inv?D.invs.find(x=>x.id==b.inv):null;if(b.inv&&(!i||!(vis(i,q.u)||q.lv>=3)))return E(s,'Investigación no válida');
const r={id:++D.seq.r,url:b.url,inv:i?i.id:null,invName:i?i.name:'',context:String(b.context).slice(0,3000),lvl:lvlIn(b.lvl)||3,by:q.u.id,byId:q.u.id,byName:`${q.u.name} (${q.u.plate})`,ts:new Date().toISOString(),shared:q.lv>=3?okIds(b.shared).filter(x=>x!=q.u.id):[]};
D.reports.push(r);L(q,'informes',r.lvl==3?'Informe enviado (NIVEL 3)':'Informe enviado',`Nº ${r.id} · Nivel ${r.lvl}${i?' · investigación '+i.name:''}`,r.inv);saveAll();s.json(rOut(r,q.u))});
app.get('/api/reports/:id/history',auth(1),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r||!canR(r,q.u)||!rEd(r,q.u))return E(s,'No existe',404);s.json({cur:{url:r.url,context:r.context},hist:(r.hist||[]).slice().reverse()})});
app.put('/api/reports/:id',auth(1),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r||!canR(r,q.u))return E(s,'No existe',404);if(!rEd(r,q.u))return E(s,'Solo el autor o un Coordinador o superior puede editar el informe',403);const b=q.body,url=String(b.url??r.url),ctx=String(b.context??r.context).trim().slice(0,3000);
if(!/^https:\/\/(docs|drive)\.google\.com\//.test(url))return E(s,'Pega un enlace válido de Google Docs');if(!ctx)return E(s,'Escribe el contexto del informe');if(url===r.url&&ctx===r.context)return s.json({});pushH(r,{url:r.url,context:r.context},q);r.url=url;r.context=ctx;L(q,'informes','Informe EDITADO',`Nº ${r.id} · versión ${r.hist.length+1}`,r.inv);saveAll();s.json({})});
app.post('/api/reports/:id/open',auth(),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r||!canR(r,q.u))return E(s,'No tienes acceso a este informe',403);
L(q,'informes','Informe abierto',`Nº ${r.id}${r.invName?' · '+r.invName:''}`,r.inv);s.json({url:r.url})});
app.put('/api/reports/:id/inv',auth(3),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id),i=q.body.inv?D.invs.find(x=>x.id==q.body.inv):null;if(!r)return E(s,'No existe',404);if(q.body.inv&&!i)return E(s,'Investigación no válida');
const old=r.invName||'ninguna';r.inv=i?i.id:null;r.invName=i?i.name:'';L(q,'informes','Informe asociado a investigación',`Nº ${r.id}: ${old} → ${r.invName||'ninguna'}${i?' (quien pueda ver la investigación ya puede ver el informe)':''}`,r.inv);saveAll();s.json({})});
// Un Coordinador o superior cambia el nivel y/o autoriza a personas concretas aunque su rango no llegue al nivel
app.put('/api/reports/:id/access',auth(3),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r)return E(s,'No existe',404);const l=lvlIn(q.body.lvl)||r.lvl||3,sh=okIds(q.body.users).filter(x=>x!=r.byId),was=r.lvl||3;
r.lvl=l;r.shared=sh;L(q,'informes','Acceso de informe modificado',`Nº ${r.id}: Nivel ${was} → Nivel ${l} · acceso especial: ${sh.map(nm).join(', ')||'nadie'}`,r.inv);saveAll();s.json({})});
app.delete('/api/reports/:id',auth(3),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r)return E(s,'No existe',404);
D.reports=D.reports.filter(x=>x!==r);L(q,'informes','Informe ELIMINADO',`Nº ${r.id} de ${r.byName}`,r.inv);saveAll();s.json({})});

// ---------- Investigaciones ----------
const okStaff=id=>D.users.some(u=>u.id==id&&staff(u));
const PH=['Apertura','Vigilancia','Análisis','Operativo','Cierre'],phOf=i=>PH.includes(i.ph)?i.ph:(i.st==='Cerrada'?'Cierre':'Apertura');
const ARCH_DAYS=30; // las investigaciones Cerradas pasan solas a «Archivadas» a los 30 días (siguen accesibles, buscables y se pueden reabrir)
const lastMap=()=>{const m=new Map();for(const l of D.logs)if(l.inv&&(l.type=='investigaciones'||l.type=='informes'||l.type=='notas'))m.set(l.inv,l.ts);return m};
const invSum=(i,u,lm)=>{const last=lm.get(i.id)||i.ts;return{id:i.id,name:i.name,desc:i.desc,st:i.st||'Abierta',pr:i.pr||'Media',ph:phOf(i),lead:i.lead,team:i.team,leadName:nm(i.lead),members:[i.lead,...i.team].map(id=>({id,name:nm(id)})),nInfo:i.info.length,nPeople:i.people.length,nRep:D.reports.filter(r=>r.inv==i.id&&canR(r,u)).length,nNotes:D.notes.filter(n=>n.inv==i.id&&nOk(n,u)).length,nFichas:(i.fichas||[]).filter(id=>D.fichas.some(f=>f.id==id)).length,ts:i.ts,last,mine:inInv(i,u),arch:(i.st||'Abierta')==='Cerrada'&&Date.now()-Date.parse(i.closedAt||last)>ARCH_DAYS*864e5}};
// Cronología: acciones sobre la investigación + informes que el usuario puede ver. En borrados/ediciones no se muestra el contenido anterior.
const tl=(i,u)=>[...D.logs.filter(l=>l.inv==i.id&&l.type=='investigaciones').slice(-40).map(l=>({ts:l.ts,act:l.act,who:l.name||'Sistema',det:/ELIMINAD|EDITAD|retirado/i.test(l.act)?'':String(l.det||'').replace(i.name+': ','')})),
...D.reports.filter(r=>r.inv==i.id&&canR(r,u)).map(r=>({ts:r.ts,act:`Informe Nº ${r.id} añadido`,who:String(r.byName).replace(/ \(.*\)$/,''),det:r.context.slice(0,90)})),
...D.notes.filter(n=>n.inv==i.id&&nOk(n,u)).map(n=>({ts:n.ts,act:`Nota informativa Nº ${n.id} añadida`,who:String(n.byName).replace(/ \(.*\)$/,''),det:n.event.slice(0,90)}))].sort((a,b)=>a.ts<b.ts?1:-1).slice(0,40);
app.get('/api/inv',auth(),(q,s)=>{const lm=lastMap();s.json(D.invs.filter(i=>(q.query.all&&q.lv>=3)||vis(i,q.u)).map(i=>invSum(i,q.u,lm)))});
app.post('/api/inv',auth(2),(q,s)=>{const b=q.body,lead=+b.lead;if(!b.name||!okStaff(lead))return E(s,'Indica nombre y mando a cargo');
const i={id:++D.seq.i,name:String(b.name).slice(0,100),desc:String(b.desc||'').slice(0,500),lead,team:[...new Set((b.team||[]).map(Number))].filter(x=>x!=lead&&okStaff(x)),info:[],people:[],st:'Abierta',pr:'Media',ph:'Apertura',ts:new Date().toISOString()};
D.invs.push(i);L(q,'investigaciones','Investigación creada',`${i.name} · mando: ${nm(lead)} · investigadores: ${i.team.map(nm).join(', ')||'—'}`,i.id);saveAll();s.json({id:i.id})});
const gi=(q,s)=>{const i=D.invs.find(x=>x.id==q.params.id);if(!i||!vis(i,q.u)){E(s,'No existe o no tienes acceso',404);return null}return i};
app.get('/api/inv/:id',auth(),(q,s)=>{const i=gi(q,s);if(!i)return;s.json({...i,info:i.info.map(x=>edI(i,q.u)?{...x,hist:(x.hist||[]).slice().reverse()}:{...x,hist:undefined}),people:i.people.map(x=>ed(i,q.u)?{...x,hist:(x.hist||[]).slice().reverse()}:{...x,hist:undefined}),ph:phOf(i),timeline:tl(i,q.u),notes:D.notes.filter(n=>n.inv==i.id&&nOk(n,q.u)).reverse().map(nSum),fichas:(i.fichas||[]).map(id=>D.fichas.find(f=>f.id==id)).filter(Boolean).map(f=>({...f,hist:undefined,files:f.files.slice(0,1)})),leadName:nm(i.lead),teamNames:i.team.map(id=>({id,name:nm(id)})),reports:D.reports.filter(r=>r.inv==i.id&&canR(r,q.u)).map(r=>rOut(r,q.u)),canManage:mg(i,q.u),canDelete:lvOf(q.u)>=5,canEdit:ed(i,q.u),canEditInfo:edI(i,q.u)})});
const W=(p,m,perm,fn)=>app[m]('/api/inv/:id'+p,auth(),(q,s)=>{const i=gi(q,s);if(!i)return;if(perm&&!perm(i,q.u))return E(s,'No tienes permisos para hacer esto',403);fn(q,s,i)});
const rid=()=>C.randomBytes(4).toString('hex');
W('/info','post',ed,(q,s,i)=>{const{k,v}=q.body;if(!k||!v)return E(s,'Completa ambos campos');i.info.push({id:rid(),k:String(k).slice(0,60),v:String(v).slice(0,500),by:q.u.name});L(q,'investigaciones','Dato añadido',`${i.name}: ${k} = ${v}`,i.id);saveAll();s.json({})});
W('/info/:x','put',edI,(q,s,i)=>{const d=i.info.find(x=>x.id==q.params.x),{k,v}=q.body;if(!d)return E(s,'No existe',404);if(!k||!v)return E(s,'Completa ambos campos');
L(q,'investigaciones','Dato EDITADO',`${i.name}: ${d.k} = ${d.v} → ${k} = ${v}`,i.id);if(String(k).slice(0,60)!==d.k||String(v).slice(0,500)!==d.v)pushH(d,{k:d.k,v:d.v},q);d.k=String(k).slice(0,60);d.v=String(v).slice(0,500);saveAll();s.json({})});
W('/info/:x','delete',mg,(q,s,i)=>{const d=i.info.find(x=>x.id==q.params.x);i.info=i.info.filter(x=>x!==d);L(q,'investigaciones','Dato ELIMINADO',`${i.name}: ${d?d.k+' = '+d.v:q.params.x}`,i.id);saveAll();s.json({})});
const imgs=a=>(a||[]).filter(f=>/^data:image\/(jpeg|png|webp|gif);base64,/.test(f)).slice(0,6);
W('/people','post',ed,(q,s,i)=>{const b=q.body;if(!b.name)return E(s,'Indica el nombre');const files=imgs(b.files);i.people.push({id:rid(),name:String(b.name).slice(0,80),role:String(b.role||'').slice(0,60),notes:String(b.notes||'').slice(0,500),files,by:q.u.name});L(q,'investigaciones','Persona involucrada añadida',`${i.name}: ${b.name}${files.length?' · '+files.length+' foto(s)':''}`,i.id);saveAll();s.json({})});
W('/people/:x','put',ed,(q,s,i)=>{const d=i.people.find(x=>x.id==q.params.x),b=q.body;if(!d)return E(s,'No existe',404);if(!b.name)return E(s,'Indica el nombre');const ch=[],snap={name:d.name,role:d.role,notes:d.notes||''};
for(const k of['name','role','notes']){const v=String(b[k]||'').slice(0,k=='name'?80:k=='role'?60:500);if(v!==(d[k]||'')){ch.push(`${k}: ${d[k]||'—'} → ${v||'—'}`);d[k]=v}}
const f=imgs(b.files);if(JSON.stringify(f)!==JSON.stringify(d.files||[])){ch.push(`fotos: ${(d.files||[]).length} → ${f.length}`);d.files=f}
if(ch.some(x=>!x.startsWith('fotos')))pushH(d,snap,q);L(q,'investigaciones','Persona involucrada EDITADA',`${i.name} · ${d.name}: ${ch.join(' | ')||'sin cambios'}`,i.id);saveAll();s.json({})});
W('/people/:x','delete',mg,(q,s,i)=>{const d=i.people.find(x=>x.id==q.params.x);i.people=i.people.filter(x=>x!==d);L(q,'investigaciones','Persona involucrada ELIMINADA',`${i.name}: ${d?d.name:q.params.x}`,i.id);saveAll();s.json({})});
W('/fichas','post',ed,(q,s,i)=>{const f=D.fichas.find(x=>x.id==q.body.fid);if(!f)return E(s,'La ficha no existe',404);i.fichas=i.fichas||[];if(i.fichas.includes(f.id))return E(s,'Esa ficha ya está vinculada');i.fichas.push(f.id);L(q,'investigaciones','Ficha vinculada',`${i.name}: ${f.type} · ${f.name}`,i.id);saveAll();s.json({})});
W('/fichas/:x','delete',ed,(q,s,i)=>{const f=D.fichas.find(x=>x.id==q.params.x);i.fichas=(i.fichas||[]).filter(x=>x!=q.params.x);L(q,'investigaciones','Ficha desvinculada',`${i.name}: ${f?f.type+' · '+f.name:q.params.x}`,i.id);saveAll();s.json({})});
// Convierte a una persona de la investigación en ficha reutilizable de la Base de datos y la vincula (como crear una ficha: Analista o superior)
W('/people/:x/ficha','post',ed,(q,s,i)=>{if(q.lv<2)return E(s,'Necesitas ser Analista o superior para crear fichas',403);const p=i.people.find(x=>x.id==q.params.x);if(!p)return E(s,'No existe',404);
// La Base de datos la ven TODOS los miembros: solo se copian nombre y fotos; las notas y la operación de la investigación NO se copian.
const f={id:D.seq.f=(D.seq.f||0)+1,type:'Persona',name:p.name,alias:'',plate:'',op:'',notes:'',files:(p.files||[]).slice(0,6),by:q.u.name,ts:new Date().toISOString()};
D.fichas.push(f);i.fichas=[...(i.fichas||[]),f.id];L(q,'fichas','Ficha creada',`Persona: ${f.name} (desde la investigación ${i.name})`,i.id);saveAll();s.json({id:f.id})});
W('/team','put',mg,(q,s,i)=>{const lead=+q.body.lead,ids=[...new Set((q.body.team||[]).map(Number))].filter(x=>x!=lead&&okStaff(x));if(!okStaff(lead))return E(s,'Mando no válido');
const add=ids.filter(x=>!i.team.includes(x)),rem=i.team.filter(x=>!ids.includes(x));
if(lead!=i.lead)L(q,'investigaciones','Cambio de mando a cargo',`${i.name}: ${nm(i.lead)} → ${nm(lead)}`,i.id);
add.forEach(x=>L(q,'investigaciones','Investigador añadido',`${i.name}: ${nm(x)}`,i.id));rem.forEach(x=>L(q,'investigaciones','Investigador retirado (pierde el acceso)',`${i.name}: ${nm(x)}`,i.id));
i.lead=lead;i.team=ids;saveAll();s.json({})});
W('','put',mg,(q,s,i)=>{const n=String(q.body.name||'').trim().slice(0,100),d=String(q.body.desc||'').trim().slice(0,500);if(!n)return E(s,'Indica el nombre de la investigación');const ch=[];
if(n!==i.name){ch.push(`nombre: ${i.name} → ${n}`);D.reports.forEach(r=>{if(r.inv==i.id)r.invName=n});D.notes.forEach(x=>{if(x.inv==i.id)x.invName=n});i.name=n}if(d!==i.desc){ch.push('descripción modificada');i.desc=d}
const b=q.body;if(['Abierta','En espera','Cerrada'].includes(b.st)&&b.st!==(i.st||'Abierta')){ch.push(`estado: ${i.st||'Abierta'} → ${b.st}`);i.st=b.st;if(b.st==='Cerrada')i.closedAt=new Date().toISOString();else delete i.closedAt}if(['Baja','Media','Alta'].includes(b.pr)&&b.pr!==(i.pr||'Media')){ch.push(`prioridad: ${i.pr||'Media'} → ${b.pr}`);i.pr=b.pr}
if(PH.includes(b.ph)&&b.ph!==phOf(i)){ch.push(`fase: ${phOf(i)} → ${b.ph}`);i.ph=b.ph}
L(q,'investigaciones','Investigación editada',`${i.name}: ${ch.join(' | ')||'sin cambios'}`,i.id);saveAll();s.json({})});
W('','delete',(i,u)=>lvOf(u)>=5,(q,s,i)=>{D.invs=D.invs.filter(x=>x!==i);D.users.forEach(u=>{u.inv=(u.inv||[]).filter(x=>x!=i.id)});L(q,'investigaciones','Investigación ELIMINADA',i.name,i.id);saveAll();s.json({})});

// ---------- Actividad: servicio (fichaje), horas y tareas ----------
// Las horas se reparten por día natural en horario de España (Europe/Madrid). Un servicio olvidado se cierra solo a las 12 h.
const TZ='Europe/Madrid',FMT=new Intl.DateTimeFormat('en-GB',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'});
const lparts=t=>{const o={};for(const p of FMT.formatToParts(new Date(t)))if(p.type!=='literal')o[p.type]=+p.value;return o},pad=n=>String(n).padStart(2,'0'),dkey=t=>{const o=lparts(t);return `${o.year}-${pad(o.month)}-${pad(o.day)}`};
const nextMid=t=>{const o=lparts(t);return t+((24-o.hour)*3600-o.minute*60-o.second)*1000},addDays=(k,n)=>new Date(Date.parse(k+'T00:00:00Z')+n*864e5).toISOString().slice(0,10),fmtH=ms=>`${Math.floor(ms/36e5)} h ${pad(Math.round(ms%36e5/6e4))} min`;
const MAX_SHIFT=12*36e5,sEnd=(x,now)=>x.end?Date.parse(x.end):Math.min(now,Date.parse(x.start)+MAX_SHIFT);
const perDay=(x,now,m)=>{let a=Date.parse(x.start);const b=sEnd(x,now);while(a<b){let n=Math.min(b,nextMid(a));if(n<=a)n=a+1000;const k=dkey(a);m[k]=(m[k]||0)+(n-a);a=n}return m};
const th=(t,type,q,text)=>{(t.hist||(t.hist=[])).push({ts:new Date().toISOString(),type,byName:q.u.name,text:text||''})};
const nid=k=>D.seq[k]=(D.seq[k]||0)+1,saveAct=()=>store.flush(D,false,true),isKey=v=>/^\d{4}-\d{2}-\d{2}$/.test(v||'');
const closeStale=()=>{const now=Date.now();let ch=false;for(const x of D.shifts)if(!x.end&&Date.parse(x.start)+MAX_SHIFT<now){x.end=new Date(Date.parse(x.start)+MAX_SHIFT).toISOString();x.auto=true;ch=true}if(ch)saveAct()};
const refreshTasks=()=>{const now=Date.now();let ch=false;for(const t of D.tasks)if(t.st==='Pendiente'&&t.due&&Date.parse(t.due)<now){t.st='No completada';t.missedAt=t.due;ch=true}if(ch)saveAct()};
const dayMap=(uid,now)=>{const m={};for(const x of D.shifts)if(x.uid==uid)perDay(x,now,m);return m},sumR=(m,a,b)=>Object.entries(m).reduce((t,[k,v])=>k>=a&&k<=b?t+v:t,0);
const periods=now=>{const t=dkey(now),wd=(new Date(t+'T00:00:00Z').getUTCDay()+6)%7,mon=addDays(t,-wd);return{today:[t,t],week:[mon,addDays(mon,6)],month:[t.slice(0,8)+'01',t.slice(0,8)+'31']}};
// Horas mínimas configurables: semanal (por defecto 3 h) y mensual (por defecto sin mínimo). 0 = sin mínimo.
const rules=()=>({week:D.settings.minWeek==null?3:Math.max(0,+D.settings.minWeek||0),month:Math.max(0,+D.settings.minMonth||0)}),prevWeek=now=>{const a=addDays(periods(now).week[0],-7);return[a,addDays(a,6)]},prevMonth=now=>{const b=addDays(periods(now).month[0],-1);return[b.slice(0,8)+'01',b]};
// Inactividad: menos de 3 h en la semana anterior (lunes a domingo). No se marca a cuentas suspendidas ni a quien se incorporó durante esa semana.
// Inactivo = por debajo del mínimo semanal (semana anterior) o mensual (mes anterior). No se marca a suspendidos, a EXENTOS ni a quien se incorporó durante ese periodo.
const inactiveOf=(u,h,now)=>{const R_=rules(),pw=prevWeek(now),pm=prevMonth(now),prev=sumR(h.days,...pw),prevM=sumR(h.days,...pm),ex=!!u.exempt,cr=u.ts?dkey(Date.parse(u.ts)):'',base=!u.susp&&!ex;return{prev,prevM,exempt:ex,inactive:base&&R_.week>0&&(!u.ts||cr<pw[0])&&prev<R_.week*36e5,inactiveM:base&&R_.month>0&&(!u.ts||cr<pm[0])&&prevM<R_.month*36e5}};
const hoursOf=(uid,now)=>{const m=dayMap(uid,now),p=periods(now);return{today:sumR(m,...p.today),week:sumR(m,...p.week),month:sumR(m,...p.month),total:sumR(m,'0000','9999'),days:m}};
const canSup=(q,u)=>staff(u)&&u.id!==q.u.id&&(q.lv>=6||rk(u)<q.lv); // a quién puede encargar tareas: solo a rangos inferiores (FL/DAO/Desarrollador con modo activo: a todos)
// Corregir servicios: lo mismo, y además un Desarrollador / Co-Desarrollador con el modo activo puede editar los SUYOS.
const canShift=(q,u)=>staff(u)&&(u.id!==q.u.id?(q.lv>=6||rk(u)<q.lv):q.lv>=7);
const shOut=(x,now)=>({id:x.id,uid:x.uid,start:x.start,end:x.end||null,open:!x.end,auto:!!x.auto,manual:!!x.manual,note:x.note||'',ms:sEnd(x,now)-Date.parse(x.start)});
const tStats=a=>{const r={total:a.length,done:0,late:0,pending:0,missed:0,cancelled:0};for(const t of a){if(t.st==='Completada'){r.done++;if(t.late)r.late++}else if(t.st==='Pendiente')r.pending++;else if(t.st==='No completada')r.missed++;else r.cancelled++}return r};
const tOut=t=>({id:t.id,gid:t.gid,title:t.title,desc:t.desc||'',by:t.by,byName:nm(t.by),to:t.to,toName:nm(t.to),ts:t.ts,due:t.due||null,pr:t.pr,st:t.st,doneAt:t.doneAt||null,late:!!t.late,note:t.note||'',inv:t.inv||null,invName:t.invName||'',hist:t.hist||[],returns:t.returns||0,returnReason:t.returnReason||'',returnedBy:t.returnedBy||'',returnedAt:t.returnedAt||null});
const rangeOf=q=>{const p=periods(Date.now()),pr=q.query.p;let a,b;if(pr==='today')[a,b]=p.today;else if(pr==='week')[a,b]=[p.week[0],p.today[1]];else if(pr==='lastmonth'){b=addDays(p.month[0],-1);a=b.slice(0,8)+'01'}else{a=isKey(q.query.from)?q.query.from:p.month[0];b=isKey(q.query.to)?q.query.to:p.today[1]}if(a>b)[a,b]=[b,a];return[a,b]};
const inR=(ts,a,b)=>{const k=dkey(Date.parse(ts));return k>=a&&k<=b};
const teamRows=(q,a,b)=>{const now=Date.now();return D.users.filter(staff).map(u=>{const h=hoursOf(u.id,now),o=D.shifts.find(x=>x.uid==u.id&&!x.end),mine=D.shifts.filter(x=>x.uid==u.id),ia=inactiveOf(u,h,now);
return{...ia,id:u.id,name:u.name,plate:u.plate,rank:rk(u)?RANKS[rk(u)-1]:'',title:SP.includes(u.role)?u.role:'',susp:!!u.susp,inService:!!o,since:o?o.start:null,today:h.today,week:h.week,month:h.month,period:sumR(h.days,a,b),shifts:mine.filter(x=>Object.keys(perDay(x,now,{})).some(k=>k>=a&&k<=b)).length,got:tStats(D.tasks.filter(t=>t.to==u.id&&inR(t.ts,a,b))),sent:tStats(D.tasks.filter(t=>t.by==u.id&&inR(t.ts,a,b))),canSup:canSup(q,u),canShift:canShift(q,u)}}).sort((x,y)=>y.period-x.period)};
// Avisos a Discord (los dispara la alarma diaria): uno por semana (<mínimo semanal) y otro por mes (<mínimo mensual). Solo se envían si hay alguien por debajo.
const weeklyInactivity=()=>{closeStale();const now=Date.now(),p=periods(now),mon=p.week[0],mk=p.month[0],R_=rules(),out=[],all=D.users.filter(staff).map(u=>({u,...inactiveOf(u,hoursOf(u.id,now),now)})),who=(r,v)=>`• ${r.u.name} (${r.u.plate}) · ${RANKS[rk(r.u)-1]||''}: ${fmtH(v)}`;let done=false;
if(D.seq.wk!==mon){D.seq.wk=mon;done=true;const pw=prevWeek(now),rows=all.filter(r=>r.inactive).sort((x,y)=>x.prev-y.prev);if(rows.length)out.push({n:rows.length,title:'Inactividad semanal',text:`Semana ${pw[0]} → ${pw[1]}: ${rows.length} agente(s) por debajo de ${R_.week} h.\n`+rows.slice(0,25).map(r=>who(r,r.prev)).join('\n')})}
if(D.seq.mk!==mk){D.seq.mk=mk;done=true;const pm=prevMonth(now),rows=all.filter(r=>r.inactiveM).sort((x,y)=>x.prevM-y.prevM);if(rows.length)out.push({n:rows.length,title:'Inactividad mensual',text:`Mes ${pm[0].slice(0,7)}: ${rows.length} agente(s) por debajo de ${R_.month} h.\n`+rows.slice(0,25).map(r=>who(r,r.prevM)).join('\n')})}
if(!done)return null;save();for(const o of out)hook(o.title,o.text,{name:'Sistema',role:'Actividad',plate:''});return{n:out.reduce((t,o)=>t+o.n,0),text:out.map(o=>o.text).join('\n\n')}};
const shIn=b=>{const st=Date.parse(b.start),en=Date.parse(b.end);if(!(st>0)||!(en>0)||en<=st||en-st>24*36e5||en>Date.now()+6e4)return null;return[new Date(st).toISOString(),new Date(en).toISOString()]};
app.get('/api/activity/me',auth(1),(q,s)=>{closeStale();refreshTasks();const now=Date.now(),u=q.u,h=hoursOf(u.id,now),o=D.shifts.find(x=>x.uid==u.id&&!x.end),k0=dkey(now),last=[];for(let i=13;i>=0;i--){const k=addDays(k0,-i);last.push({d:k,ms:h.days[k]||0})}
s.json({canServe:staff(u),weekMin:rules().week,monthMin:rules().month,...inactiveOf(u,h,now),open:o?{id:o.id,start:o.start}:null,now:new Date(now).toISOString(),today:h.today,week:h.week,month:h.month,total:h.total,last,recent:D.shifts.filter(x=>x.uid==u.id).slice(-25).reverse().map(x=>shOut(x,now)),tasks:{pending:D.tasks.filter(t=>t.to==u.id&&t.st==='Pendiente').length,missed:D.tasks.filter(t=>t.to==u.id&&t.st==='No completada').length}})});
app.post('/api/activity/start',auth(1),(q,s)=>{if(!staff(q.u))return E(s,'Necesitas un rango CGI para registrar servicio',403);closeStale();if(D.shifts.some(x=>x.uid==q.u.id&&!x.end))return E(s,'Ya tienes un servicio iniciado');const x={id:nid('sh'),uid:q.u.id,start:new Date().toISOString(),end:null};D.shifts.push(x);L(q,'actividad','Servicio iniciado','');saveAct();s.json({id:x.id,start:x.start})});
app.post('/api/activity/stop',auth(1),(q,s)=>{const x=D.shifts.find(y=>y.uid==q.u.id&&!y.end);if(!x)return E(s,'No tienes ningún servicio iniciado');x.end=new Date().toISOString();x.note=String(q.body.note||'').slice(0,200);const d=sEnd(x,Date.now())-Date.parse(x.start);L(q,'actividad','Servicio finalizado',`Duración ${fmtH(d)}`);saveAct();s.json({ms:d})});
// --- zona de supervisión (Coordinador o superior) ---
app.get('/api/activity/team',auth(3),(q,s)=>{closeStale();refreshTasks();const[a,b]=rangeOf(q),rows=teamRows(q,a,b);s.json({from:a,to:b,rows,weekMin:rules().week,monthMin:rules().month,totals:{period:rows.reduce((t,r)=>t+r.period,0),inService:rows.filter(r=>r.inService).length,inactive:rows.filter(r=>r.inactive||r.inactiveM).length}})});
app.get('/api/activity/export',auth(3),(q,s)=>{closeStale();refreshTasks();const[a,b]=rangeOf(q),h=ms=>(ms/36e5).toFixed(2).replace('.',',');
const rows=[['nombre','placa','rango','titulo_especial','en_servicio','horas_periodo','horas_hoy','horas_semana','horas_mes','turnos_periodo','tareas_recibidas','completadas','completadas_fuera_de_plazo','pendientes','no_completadas','canceladas','tareas_enviadas','enviadas_completadas','enviadas_pendientes','enviadas_no_completadas','horas_semana_pasada','inactivo_semana_pasada','horas_mes_pasado','inactivo_mes_pasado','exento'],...teamRows(q,a,b).map(r=>[r.name,r.plate,r.rank,r.title,r.inService?'sí':'no',h(r.period),h(r.today),h(r.week),h(r.month),r.shifts,r.got.total,r.got.done,r.got.late,r.got.pending,r.got.missed,r.got.cancelled,r.sent.total,r.sent.done,r.sent.pending,r.sent.missed,h(r.prev),r.inactive?'sí':'no',h(r.prevM),r.inactiveM?'sí':'no',r.exempt?'sí':'no'])];
L(q,'actividad','Informe de actividad descargado',`Periodo ${a} → ${b} · ${rows.length-1} perfiles`);s.set({'Content-Type':'text/csv; charset=utf-8','Content-Disposition':`attachment; filename="actividad-cgi-${a}_${b}.csv"`}).send(csv(rows))});
app.get('/api/activity/user/:id',auth(3),(q,s)=>{closeStale();refreshTasks();const u=D.users.find(x=>x.id==q.params.id);if(!u||!staff(u))return E(s,'No existe',404);const now=Date.now(),[a,b]=rangeOf(q),h=hoursOf(u.id,now);
s.json({id:u.id,name:u.name,plate:u.plate,exempt:!!u.exempt,from:a,to:b,period:sumR(h.days,a,b),days:Object.entries(h.days).filter(([k])=>k>=a&&k<=b).sort().map(([d,ms])=>({d,ms})),shifts:D.shifts.filter(x=>x.uid==u.id&&Object.keys(perDay(x,now,{})).some(k=>k>=a&&k<=b)).reverse().map(x=>shOut(x,now)),tasks:D.tasks.filter(t=>t.to==u.id||t.by==u.id).slice(-60).reverse().map(tOut),canSup:canSup(q,u),canShift:canShift(q,u)})});
app.post('/api/activity/shifts',auth(3),(q,s)=>{const u=D.users.find(x=>x.id==q.body.uid);if(!u||!canShift(q,u))return E(s,'No puedes gestionar la actividad de ese perfil',403);const r=shIn(q.body);if(!r)return E(s,'Fechas no válidas (máximo 24 h por turno y no en el futuro)');
const x={id:nid('sh'),uid:u.id,start:r[0],end:r[1],manual:true,note:String(q.body.note||'').slice(0,200),by:q.u.id};D.shifts.push(x);L(q,'actividad','Turno añadido manualmente',`${u.name}: ${fmtH(Date.parse(r[1])-Date.parse(r[0]))}`);saveAct();s.json({id:x.id})});
const shGet=(q,s)=>{const x=D.shifts.find(y=>y.id==q.params.id),u=x&&D.users.find(z=>z.id==x.uid);if(!x||!u){E(s,'No existe',404);return null}if(!canShift(q,u)){E(s,'No puedes gestionar la actividad de ese perfil',403);return null}return[x,u]};
app.put('/api/activity/shifts/:id',auth(3),(q,s)=>{const g=shGet(q,s);if(!g)return;const[x,u]=g;if(!x.end)return E(s,'Ese servicio sigue abierto: ciérralo primero');const r=shIn(q.body);if(!r)return E(s,'Fechas no válidas (máximo 24 h por turno y no en el futuro)');
const old=fmtH(sEnd(x,Date.now())-Date.parse(x.start));x.start=r[0];x.end=r[1];x.manual=true;x.note=String(q.body.note??x.note??'').slice(0,200);L(q,'actividad','Turno corregido',`${u.name}: ${old} → ${fmtH(Date.parse(r[1])-Date.parse(r[0]))}`);saveAct();s.json({})});
app.delete('/api/activity/shifts/:id',auth(3),(q,s)=>{const g=shGet(q,s);if(!g)return;const[x,u]=g;D.shifts=D.shifts.filter(y=>y!==x);L(q,'actividad','Turno ELIMINADO',`${u.name}: ${fmtH(sEnd(x,Date.now())-Date.parse(x.start))} (${x.start.slice(0,10)})`);saveAct();s.json({})});
app.post('/api/activity/user/:id/stop',auth(3),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u||!canShift(q,u))return E(s,'No puedes gestionar la actividad de ese perfil',403);const x=D.shifts.find(y=>y.uid==u.id&&!y.end);if(!x)return E(s,'Ese perfil no está en servicio');
x.end=new Date().toISOString();x.note='Cerrado por '+q.u.name;L(q,'actividad','Servicio cerrado por un superior',`${u.name}: ${fmtH(sEnd(x,Date.now())-Date.parse(x.start))}`);saveAct();s.json({})});
// Comisario General o superior: fija los mínimos y exime a quien no deba cumplirlos
app.put('/api/activity/rules',auth(5),(q,s)=>{const w=+q.body.week,m=+q.body.month;if(!(w>=0&&w<=168)||!(m>=0&&m<=744))return E(s,'Indica horas válidas: semanal de 0 a 168 y mensual de 0 a 744 (0 = sin mínimo)');const old=rules();D.settings.minWeek=Math.round(w*4)/4;D.settings.minMonth=Math.round(m*4)/4;
L(q,'actividad','Horas mínimas modificadas',`semanal: ${old.week} → ${D.settings.minWeek} h · mensual: ${old.month} → ${D.settings.minMonth} h`);saveAll();s.json(rules())});
app.put('/api/activity/exempt/:id',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u||!staff(u))return E(s,'No existe',404);if(u.id===q.u.id&&q.lv<7)return E(s,'No puedes eximirte a ti mismo/a',403);const ex=!!q.body.exempt;if(ex===!!u.exempt)return s.json({});if(ex)u.exempt=true;else delete u.exempt;
L(q,'actividad',ex?'Exención de horas mínimas concedida':'Exención de horas mínimas retirada',u.name);save();s.json({})});
// --- tareas ---
app.get('/api/tasks',auth(1),(q,s)=>{refreshTasks();const sc=q.query.scope,me=q.u.id;let a=D.tasks;if(sc==='sent')a=a.filter(t=>t.by==me);else if(sc==='all'){if(q.lv<3)return E(s,'Sin permisos',403)}else a=a.filter(t=>t.to==me);s.json(a.slice().reverse().map(tOut))});
app.post('/api/tasks',auth(3),(q,s)=>{const b=q.body,title=String(b.title||'').trim().slice(0,120);if(!title)return E(s,'Escribe el título de la tarea');const ids=[...new Set((b.to||[]).map(Number))].slice(0,30);if(!ids.length)return E(s,'Elige a quién encargas la tarea');
const us=ids.map(id=>D.users.find(u=>u.id==id));if(us.some(u=>!u||!canSup(q,u)))return E(s,'Solo puedes encargar tareas a tus subordinados',403);
let due=null;if(b.due){const d=Date.parse(b.due);if(!(d>Date.now()))return E(s,'El plazo debe ser una fecha futura');due=new Date(d).toISOString()}
const i=b.inv?D.invs.find(x=>x.id==b.inv):null;if(b.inv&&(!i||!(vis(i,q.u)||q.lv>=3)))return E(s,'Investigación no válida');
const gid=nid('tg'),ts=new Date().toISOString();for(const u of us){const t={id:nid('tk'),gid,title,desc:String(b.desc||'').slice(0,1500),by:q.u.id,to:u.id,ts,due,pr:['Baja','Media','Alta'].includes(b.pr)?b.pr:'Media',st:'Pendiente',inv:i?i.id:null,invName:i?i.name:''};th(t,'asignada',q,due?'Plazo '+due:'Sin plazo');D.tasks.push(t)}
L(q,'actividad','Tarea asignada',`«${title}» → ${us.map(u=>u.name).join(', ')}${due?' · plazo '+due:''}`,i?i.id:undefined);saveAct();s.json({n:us.length,gid})});
app.post('/api/tasks/:id/done',auth(1),(q,s)=>{refreshTasks();const t=D.tasks.find(x=>x.id==q.params.id);if(!t||t.to!=q.u.id)return E(s,'No existe',404);if(t.st==='Completada'||t.st==='Cancelada')return E(s,'Esta tarea ya está cerrada');
const now=Date.now();t.late=!!t.due&&now>Date.parse(t.due);t.st='Completada';t.doneAt=new Date(now).toISOString();t.note=String(q.body.note||'').slice(0,500);delete t.returnReason;th(t,'completada',q,t.note+(t.late?' (fuera de plazo)':''));L(q,'actividad','Tarea completada',`«${t.title}»${t.late?' (FUERA DE PLAZO)':''} · encargada por ${nm(t.by)}`);saveAct();s.json(tOut(t))});
const tGet=(q,s)=>{const t=D.tasks.find(x=>x.id==q.params.id),u=t&&D.users.find(z=>z.id==t.to);if(!t){E(s,'No existe',404);return null}if(!(t.by==q.u.id||q.lv>=7||(q.lv>=4&&u&&canSup(q,u)))){E(s,'Solo quien la encargó (o un superior) puede modificarla',403);return null}return t};
app.put('/api/tasks/:id',auth(3),(q,s)=>{refreshTasks();const t=tGet(q,s);if(!t)return;if(t.st==='Completada'||t.st==='Cancelada')return E(s,'La tarea ya está cerrada: reábrela para modificarla');const b=q.body,ch=[];
const ti=String(b.title??t.title).trim().slice(0,120);if(!ti)return E(s,'El título no puede estar vacío');if(ti!==t.title){ch.push('título');t.title=ti}
if(b.desc!==undefined&&String(b.desc).slice(0,1500)!==t.desc){t.desc=String(b.desc).slice(0,1500);ch.push('descripción')}
if(['Baja','Media','Alta'].includes(b.pr)&&b.pr!==t.pr){t.pr=b.pr;ch.push('prioridad')}
if(b.due!==undefined){let d=null;if(b.due){const x=Date.parse(b.due);if(!(x>Date.now()))return E(s,'El plazo debe ser una fecha futura');d=new Date(x).toISOString()}if(d!==t.due){ch.push(`plazo: ${t.due||'sin plazo'} → ${d||'sin plazo'}`);t.due=d;if(t.st==='No completada'){t.st='Pendiente';delete t.missedAt}}}
if(ch.length)L(q,'actividad','Tarea modificada',`«${t.title}» (${nm(t.to)}): ${ch.join(', ')}`);saveAct();s.json(tOut(t))});
app.post('/api/tasks/:id/cancel',auth(3),(q,s)=>{refreshTasks();const t=tGet(q,s);if(!t)return;if(t.st==='Completada'||t.st==='Cancelada')return E(s,'La tarea ya está cerrada');t.st='Cancelada';t.cancelledAt=new Date().toISOString();th(t,'cancelada',q,'');L(q,'actividad','Tarea cancelada',`«${t.title}» (${nm(t.to)})`);saveAct();s.json(tOut(t))});
app.post('/api/tasks/:id/reopen',auth(3),(q,s)=>{refreshTasks();const t=tGet(q,s);if(!t)return;if(t.st==='Pendiente')return E(s,'La tarea ya está abierta');let d=null;if(q.body.due){const x=Date.parse(q.body.due);if(!(x>Date.now()))return E(s,'El plazo debe ser una fecha futura');d=new Date(x).toISOString()}
t.st='Pendiente';t.due=d;t.late=false;delete t.doneAt;th(t,'reabierta',q,d?'Nuevo plazo '+d:'Sin plazo');delete t.missedAt;delete t.cancelledAt;L(q,'actividad','Tarea reabierta',`«${t.title}» (${nm(t.to)})${d?' · nuevo plazo '+d:''}`);saveAct();s.json(tOut(t))});

// Solo un Desarrollador / Co-Desarrollador (modo activo) puede ELIMINAR tareas (de prueba o erróneas): se borran y queda constancia en los logs
app.delete('/api/tasks/:id',auth(7),(q,s)=>{const t=D.tasks.find(x=>x.id==q.params.id);if(!t)return E(s,'No existe',404);D.tasks=D.tasks.filter(x=>x!==t);L(q,'actividad','Tarea ELIMINADA',`«${t.title}» · asignada a ${nm(t.to)} por ${nm(t.by)} · estado ${t.st}`);saveAct();s.json({})});
// Devolver una tarea dada por completada pero no hecha correctamente: el motivo es obligatorio y lo ve quien la hizo
app.post('/api/tasks/:id/return',auth(3),(q,s)=>{refreshTasks();const t=tGet(q,s);if(!t)return;if(t.st!=='Completada')return E(s,'Solo se pueden devolver tareas completadas');const reason=String(q.body.reason||'').trim().slice(0,500);if(reason.length<3)return E(s,'Indica el motivo de la devolución');
let d=t.due;if(q.body.due){const x=Date.parse(q.body.due);if(!(x>Date.now()))return E(s,'El plazo debe ser una fecha futura');d=new Date(x).toISOString()}else if(t.due&&Date.parse(t.due)<Date.now())return E(s,'El plazo anterior ya venció: indica un nuevo plazo');
t.st='Pendiente';t.due=d||null;t.late=false;t.returns=(t.returns||0)+1;t.returnReason=reason;t.returnedBy=q.u.name;t.returnedAt=new Date().toISOString();delete t.doneAt;th(t,'devuelta',q,reason);
L(q,'actividad','Tarea devuelta',`«${t.title}» (${nm(t.to)}): ${reason}`);saveAct();s.json(tOut(t))});

// ---------- Sospechas del Cuerpo Nacional de Policía (formulario PÚBLICO, sin iniciar sesión) ----------
const TIP_REASONS=['Actividad criminal sospechosa','Posible corrupción o abuso de autoridad','Filtración de información o infiltración','Comportamiento sospechoso de un agente','Otro motivo'],TIP_ST=['Nueva','En revisión','Investigando','Archivada'],TIPRL=new Map();
app.get('/api/public/tips/config',(q,s)=>s.json({reasons:TIP_REASONS}));
// Defensas: campo trampa (honeypot), máx. 5 envíos por hora y por IP, máx. 200 al día, fotos validadas y con tope de tamaño
app.post('/api/public/tips',(q,s)=>{const b=q.body||{};if(b.web)return s.json({ok:true,num:0});
const now=Date.now(),k=ip(q)||'anon',recent=(TIPRL.get(k)||[]).filter(t=>now-t<36e5);if(recent.length>=5)return E(s,'Has enviado demasiados informes en poco tiempo. Inténtalo de nuevo más tarde.',429);
if(D.tips.filter(t=>now-Date.parse(t.ts)<864e5).length>=200)return E(s,'El servicio está saturado. Inténtalo de nuevo más tarde.',429);
const f=(v,n)=>String(v==null?'':v).trim().slice(0,n),discord=f(b.discord,60),roblox=f(b.roblox,60),plate=f(b.plate,20),rank=f(b.rank,40),reason=f(b.reason,80),suspects=f(b.suspects,500),when=f(b.when,200),desc=f(b.desc,4000);
if(discord.length<2)return E(s,'Indica tu usuario de Discord');if(roblox.length<2)return E(s,'Indica tu usuario de Roblox');if(!plate)return E(s,'Indica tu número de placa');if(!rank)return E(s,'Indica tu rango');if(!TIP_REASONS.includes(reason))return E(s,'Selecciona el motivo del informe');if(desc.length<10)return E(s,'Describe qué has observado (mínimo 10 caracteres)');
const fl=Array.isArray(b.files)?b.files:[];if(fl.length>6)return E(s,'Máximo 6 fotos');if(fl.some(x=>typeof x!=='string'||!/^data:image\/(jpeg|png|webp|gif);base64,/.test(x)||x.length>1.6e6))return E(s,'Alguna foto no es válida o es demasiado grande');const isImg=x=>typeof x==='string'&&/^data:image\/(jpeg|png|webp|gif);base64,/.test(x)&&x.length<=1.6e6;
// Sospechosos (hasta 10; todos los campos opcionales; las fichas totalmente vacías se descartan). El DNI admite foto.
const people=(Array.isArray(b.people)?b.people:[]).slice(0,10).map(p=>({roblox:f(p&&p.roblox,60),discord:f(p&&p.discord,60),dni:f(p&&p.dni,30),dniPhoto:p&&p.dniPhoto?p.dniPhoto:'',desc:f(p&&p.desc,1000),weapon:f(p&&p.weapon,200),fines:f(p&&p.fines,300),notes:f(p&&p.notes,1000)})).filter(p=>p.roblox||p.discord||p.dni||p.dniPhoto||p.desc||p.weapon||p.fines||p.notes);
if(people.some(p=>p.dniPhoto&&!isImg(p.dniPhoto)))return E(s,'Alguna foto del DNI no es válida o es demasiado grande');
if(fl.reduce((t,x)=>t+x.length,0)+people.reduce((t,p)=>t+p.dniPhoto.length,0)>7e6)return E(s,'Las fotos ocupan demasiado');
const t={id:nid('tp'),ts:new Date(now).toISOString(),st:'Nueva',discord,roblox,plate,rank,reason,suspects,when,desc,files:fl,people,team:[],ipc:ipx(ip(q)),comments:[]};D.tips.push(t);recent.push(now);TIPRL.set(k,recent);
if(TIPRL.size>5000)for(const[x,v]of TIPRL)if(!v.some(y=>now-y<36e5))TIPRL.delete(x);L(q,'sospechas','Sospecha recibida',`Nº ${t.id} · ${reason} · ${people.length} sospechoso(s) · ${fl.length} foto(s)`);saveAll();s.json({ok:true,num:t.id})});
// Desde Alumno ven las sospechas y pueden ASIGNARSE como investigadores; quien investiga (o un Coordinador o superior) cambia el estado y comenta.
// Un Coordinador o superior también asigna a otros. Borrar: Comisario General o superior.
const tipTeam=t=>(t.team||[]).map(id=>{const u=D.users.find(x=>x.id==id);return u?{id:u.id,name:u.name,plate:u.plate,rank:SP.includes(u.role)?u.rank:u.role}:null}).filter(Boolean);
const tipSum=(t,u)=>({id:t.id,ts:t.ts,st:t.st,reason:t.reason,discord:t.discord,roblox:t.roblox,plate:t.plate,rank:t.rank,nFiles:t.files.length,nPeople:(t.people||[]).length,nComments:(t.comments||[]).length,team:tipTeam(t),mine:(t.team||[]).includes(u.id)});
const tipWork=(t,u)=>lvOf(u)>=3||(t.team||[]).includes(u.id);
const tipGet=(q,s)=>{const t=D.tips.find(x=>x.id==q.params.id);if(!t)E(s,'No existe',404);return t};
app.get('/api/tips',auth(1),(q,s)=>{const st=q.query.st;s.json(D.tips.filter(t=>!st||t.st===st).slice().reverse().map(t=>tipSum(t,q.u)))});
app.get('/api/tips/:id',auth(1),(q,s)=>{const t=tipGet(q,s);if(t)s.json({...t,team:tipTeam(t),mine:(t.team||[]).includes(q.u.id),canWork:tipWork(t,q.u),canJoin:staff(q.u),canManage:q.lv>=3,canDelete:q.lv>=5})});
app.put('/api/tips/:id',auth(1),(q,s)=>{const t=tipGet(q,s);if(!t)return;if(!tipWork(t,q.u))return E(s,'Solo quien investiga la sospecha (o un Coordinador o superior) puede cambiar el estado',403);if(!TIP_ST.includes(q.body.st))return E(s,'Estado no válido');if(t.st!==q.body.st){const o=t.st;t.st=q.body.st;L(q,'sospechas','Sospecha: estado cambiado',`Nº ${t.id}: ${o} → ${t.st}`)}saveAll();s.json({})});
app.post('/api/tips/:id/comment',auth(1),(q,s)=>{const t=tipGet(q,s);if(!t)return;if(!tipWork(t,q.u))return E(s,'Solo quien investiga la sospecha (o un Coordinador o superior) puede comentar',403);const x=String(q.body.text||'').trim().slice(0,1000);if(!x)return E(s,'Escribe el comentario');(t.comments||(t.comments=[])).push({ts:new Date().toISOString(),by:q.u.name,text:x});L(q,'sospechas','Sospecha: comentario añadido',`Nº ${t.id}`);saveAll();s.json({})});
app.post('/api/tips/:id/join',auth(1),(q,s)=>{const t=tipGet(q,s);if(!t)return;if(!staff(q.u))return E(s,'Necesitas un rango CGI para investigar',403);t.team=t.team||[];if(t.team.includes(q.u.id))return s.json({});t.team.push(q.u.id);if(t.st==='Nueva')t.st='Investigando';L(q,'sospechas','Sospecha: investigador asignado',`Nº ${t.id}: ${q.u.name} se asigna como investigador/a`);saveAll();s.json({})});
app.post('/api/tips/:id/leave',auth(1),(q,s)=>{const t=tipGet(q,s);if(!t)return;if(!(t.team||[]).includes(q.u.id))return s.json({});t.team=t.team.filter(x=>x!=q.u.id);L(q,'sospechas','Sospecha: investigador retirado',`Nº ${t.id}: ${q.u.name} deja de investigar`);saveAll();s.json({})});
app.put('/api/tips/:id/team',auth(3),(q,s)=>{const t=tipGet(q,s);if(!t)return;const ids=okIds(q.body.users).filter(id=>staff(D.users.find(u=>u.id==id)));t.team=ids;if(ids.length&&t.st==='Nueva')t.st='Investigando';L(q,'sospechas','Sospecha: equipo de investigación modificado',`Nº ${t.id}: ${ids.map(nm).join(', ')||'nadie'}`);saveAll();s.json({})});
app.delete('/api/tips/:id',auth(5),(q,s)=>{const t=tipGet(q,s);if(!t)return;D.tips=D.tips.filter(x=>x!==t);L(q,'sospechas','Sospecha ELIMINADA',`Nº ${t.id} · ${t.reason}`);saveAll();s.json({})});
// ---------- Notas informativas de aspirantes ----------
// Rango «Aspirante» (el más bajo): solo accede a esta zona y solo ve SUS notas. Coordinador o superior ve las de todos. La numeración es común a todos los aspirantes.
const anSum=n=>({id:n.id,by:n.by,byName:n.byName,when:n.when,ts:n.ts,event:n.event.slice(0,260),nFiles:n.files.length});
app.get('/api/aspirantes/notes',auth(),(q,s)=>{const all=q.lv>=3;if(!all&&q.u.role!=='Aspirante')return E(s,'Sin permisos',403);const w=String(q.query.q||'').toLowerCase();let a=D.anotes.filter(n=>all||n.by==q.u.id);
const authors=all?Object.values(a.reduce((m,n)=>{(m[n.by]=m[n.by]||{id:n.by,name:n.byName,n:0}).n++;return m},{})):undefined;if(q.query.by)a=a.filter(n=>n.by==q.query.by);if(w)a=a.filter(n=>`${n.id} ${n.event} ${n.byName}`.toLowerCase().includes(w));s.json({notes:a.slice().reverse().map(anSum),authors})});
app.get('/api/aspirantes/notes/:id',auth(),(q,s)=>{const n=D.anotes.find(x=>x.id==q.params.id);if(!n||!(q.lv>=3||n.by==q.u.id))return E(s,'No existe',404);s.json(n)});
app.post('/api/aspirantes/notes',auth(),(q,s)=>{if(q.u.role!=='Aspirante')return E(s,'Solo los aspirantes envían notas de aspirante',403);const b=q.body,ev=String(b.event||'').trim().slice(0,6000);if(!b.when||!ev)return E(s,'Indica día/hora y suceso');
const files=(b.files||[]).filter(f=>/^data:image\/(jpeg|png|webp|gif);base64,/.test(f)).slice(0,12),n={id:nid('an'),by:q.u.id,byName:`${q.u.name} (${q.u.plate})`,when:String(b.when).slice(0,40),event:ev,files,ts:new Date().toISOString()};
D.anotes.push(n);L(q,'aspirantes','Nota de aspirante creada',`Nº ${n.id} · ${files.length} archivo(s)`);saveAll();s.json({id:n.id})});
app.delete('/api/aspirantes/notes/:id',auth(5),(q,s)=>{const n=D.anotes.find(x=>x.id==q.params.id);if(!n)return E(s,'No existe',404);D.anotes=D.anotes.filter(x=>x!==n);L(q,'aspirantes','Nota de aspirante ELIMINADA',`Nº ${n.id} de ${n.byName}`);saveAll();s.json({})});

// ---------- Búsqueda global (solo muestra lo que el usuario puede ver) ----------
app.get('/api/search',auth(),(q,s)=>{const w=String(q.query.q||'').trim().toLowerCase().slice(0,60);if(w.length<2)return s.json({groups:[]});const u=q.u,has=(...a)=>a.join(' ').toLowerCase().includes(w),cut=t=>{t=String(t||'');const i=t.toLowerCase().indexOf(w),a=Math.max(0,i-40);return i<0?t.slice(0,110):(a?'…':'')+t.slice(a,a+110)};
const g=[],add=(k,label,rows)=>{if(rows.length)g.push({k,label,rows:rows.slice(0,8)})};
add('invs','Investigaciones',D.invs.filter(i=>vis(i,u)&&has(i.name,i.desc,nm(i.lead),...i.info.map(x=>x.k+' '+x.v),...i.people.map(p=>p.name+' '+p.role+' '+p.notes))).map(i=>{const di=i.info.find(x=>has(x.k,x.v)),pe=i.people.find(p=>has(p.name,p.role,p.notes));return{id:i.id,title:i.name,sub:has(i.name,i.desc)?`${i.st||'Abierta'} · ${phOf(i)}`:di?`Dato · ${di.k}: ${di.v}`:pe?`Persona · ${pe.name}`:`Mando · ${nm(i.lead)}`}}));
if(q.lv>=1)add('notes','Notas informativas',D.notes.filter(n=>nOk(n,u)&&has(n.id,n.event,n.byName,n.invName||'')).reverse().map(n=>({id:n.id,title:`Nota Nº ${n.id} · ${n.byName}`,sub:cut(n.event),lvl:n.lvl||3})));
add('reports','Informes',D.reports.filter(r=>canR(r,u)&&has(r.id,r.context,r.byName,r.invName||'')).reverse().map(r=>({id:r.id,title:`Informe Nº ${r.id}${r.invName?' · '+r.invName:''}`,sub:cut(r.context),lvl:r.lvl||3})));
if(q.lv>=1){add('fichas','Base de datos',D.fichas.filter(f=>has(f.name,f.alias,f.plate,f.op,f.notes)).reverse().map(f=>({id:f.id,title:`${f.type} · ${f.name}`,sub:f.alias||f.plate||cut(f.notes)||f.op})));
add('plates','Placas CGI',D.users.filter(x=>staff(x)&&has(x.name,x.plate,x.discord)).map(x=>({id:x.id,title:`${x.name} · ${x.plate}`,sub:SP.includes(x.role)?`${x.role} · ${x.rank}`:x.role})))}
s.json({groups:g})});

return { handle: (request) => app.handle(request), autoSnapshot: autoSnap, backupJson: () => JSON.stringify(D), weeklyInactivity, noteOffsite: (o) => { D.seq.off = o; save(); } };
}
