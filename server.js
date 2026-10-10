'use strict';
/* XBOST 9.0. Production secrets live exclusively in Render Environment. */
const http=require('node:http'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {promisify}=require('node:util');const scrypt=promisify(crypto.scrypt);
const {createStore}=require('./db');const Ach=require('./achievements');
const PRODUCTION=process.env.NODE_ENV==='production';
const SECRET=process.env.SESSION_SECRET||'',FOUNDER_HASH=process.env.FOUNDER_PASSWORD_HASH||'';
if(!SECRET||SECRET.length<24)throw Error('SESSION_SECRET must contain at least 24 characters');
if(!FOUNDER_HASH.startsWith('scrypt$'))throw Error('FOUNDER_PASSWORD_HASH must be a scrypt hash');
const store=createStore(),COOKIE='xbost_session',PUBLIC=path.join(__dirname,'public');
const now=()=>new Date().toISOString(),sha=s=>crypto.createHash('sha256').update(String(s)).digest('hex');
const random=()=>crypto.randomBytes(32).toString('base64url');
function code(){return crypto.randomBytes(20).toString('hex').toUpperCase().match(/.{1,5}/g).join('-');}
function normCode(v){return String(v||'').replace(/[\s-]/g,'').toUpperCase();}
function fail(status,error,extra){throw Object.assign(new Error(error),{status,error,...extra});}
function cleanNick(s){const nick=String(s||'').normalize('NFKC').trim().replace(/\s+/g,' ');if(nick.length<2||nick.length>24||!/^\p{L}[\p{L}\p{N}_.\- ]*$/u.test(nick))fail(400,'bad_nickname');const norm=nick.toLocaleLowerCase('ru-RU');if(['admin','founder','основатель','xbost','щищ','system','система'].includes(norm))fail(400,'bad_nickname');return {nick,norm};}
async function verifyPassword(value,encoded){const [scheme,salt,hash]=String(encoded||'').split('$');if(scheme!=='scrypt'||!salt||!hash)return false;try{const expected=Buffer.from(hash,'base64url');if(expected.length<16||expected.length>128)return false;const got=await scrypt(String(value||''),Buffer.from(salt,'base64url'),expected.length);return crypto.timingSafeEqual(got,expected);}catch(_){return false;}}
function parseCookie(req){for(const bit of String(req.headers.cookie||'').split(';')){const at=bit.indexOf('=');if(bit.slice(0,at).trim()===COOKIE)try{return decodeURIComponent(bit.slice(at+1).trim());}catch(_){return '';}}return '';}
function cookie(res,value,maxAge=2592000){res.setHeader('Set-Cookie',`${COOKIE}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${PRODUCTION?'; Secure':''}`);}
async function issueSession(tx,res,role,user){const token=random(),record={role,playerId:user?.id||null,authVersion:user?.authVersion||1,csrf:random(),expires:Date.now()+(role==='founder'?7:30)*86400000};await tx.set('session:'+sha(token),record);cookie(res,token,role==='founder'?604800:2592000);return record;}
function legacySession(token){try{const [body,sig,tail]=token.split('.');if(tail||!body||!sig)return null;const exp=crypto.createHmac('sha256',SECRET).update(body).digest('base64url');if(sig.length!==exp.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(exp)))return null;const s=JSON.parse(Buffer.from(body,'base64url'));return s.exp>Date.now()?s:null;}catch(_){return null;}}
async function session(tx,req,res,migrate=false){const token=parseCookie(req);if(!token)return null;let s=await tx.get('session:'+sha(token));
 if(!s&&migrate){const m=await tx.get('migration:v8'),legacy=m&&Date.now()-new Date(m.at).getTime()<14*86400000?legacySession(token):null;
  if(legacy?.role==='player'){const p=await tx.get('player:'+legacy.playerId);if(p?.legacy&&!p.recoveryHash)s=await issueSession(tx,res,'player',p);}
 }
 if(!s||s.expires<Date.now())return null;if(s.role==='player'){const p=await tx.get('player:'+s.playerId);if(!p||p.authVersion!==s.authVersion)return null;s.player=p;}return s;
}
function publicUser(p){return {role:'player',id:p.id,nickname:p.nickname,needsRecoverySetup:!p.recoveryHash,tutorial:p.tutorial||{step:0}};}
async function required(tx,req,res,role,write=false){const s=await session(tx,req,res);if(!s||(role&&s.role!==role))fail(401,'unauthorized');if(write&&req.headers['x-xbost-csrf']!==s.csrf)fail(403,'csrf');return s;}
async function meta(tx){let m=await tx.get('meta');if(!m){m={schema:9,epoch:1,dataRevision:0,createdAt:now()};await tx.set('meta',m);}return m;}
async function bump(tx,m){m.dataRevision++;await tx.set('meta',m);}
async function rate(tx,req,bucket,max,ms){const parts=String(req.headers['x-forwarded-for']||'').split(',');const ip=(parts.pop()||'').trim()||req.socket.remoteAddress||'?';const key='rate:'+bucket+':'+sha(ip).slice(0,24);let r=await tx.get(key);if(!r||r.until<Date.now())r={n:0,until:Date.now()+ms};if(r.n>=max)return false;r.n++;await tx.set(key,r);return true;}
async function body(req){if(!String(req.headers['content-type']||'').startsWith('application/json'))fail(415,'json_required');let n=0,chunks=[];for await(const c of req){n+=c.length;if(n>2500000)fail(413,'payload_too_large');chunks.push(c);}try{return JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}');}catch(_){fail(400,'invalid_json');}}
function originCheck(req){if(['GET','HEAD','OPTIONS'].includes(req.method))return;const origin=req.headers.origin;if(!origin)return;let u;try{u=new URL(origin);}catch(_){fail(403,'origin');}const allowed=process.env.PUBLIC_ORIGIN?new URL(process.env.PUBLIC_ORIGIN).host:req.headers.host;if(u.host!==allowed)fail(403,'origin');}
function securityHeaders(res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('X-Frame-Options','SAMEORIGIN');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');if(PRODUCTION)res.setHeader('Strict-Transport-Security','max-age=15552000');}
function send(res,status,data,type='application/json; charset=utf-8'){const b=Buffer.from(type.startsWith('application/json')?JSON.stringify(data):String(data));res.writeHead(status,{'Content-Type':type,'Content-Length':b.length,'Cache-Control':'no-store'});res.end(b);}
const clone=x=>JSON.parse(JSON.stringify(x));
function validateGame(g,old){if(g===null)return;if(!g||Array.isArray(g)||g.version!==90||g.training||!g.team||!g.competitors||!g.runId)fail(400,'invalid_game');if(!Number.isInteger(g.turn)||g.turn<1||g.turn>20||!Number.isInteger(g.stage)||g.stage<0||g.stage>4)fail(400,'invalid_game');for(const k of ['cash','debt','inventory','soldTotal','totalRevenue','awareness','quality','hype','loyalty','cult'])if(!Number.isFinite(g[k])||Math.abs(g[k])>1e12)fail(400,'invalid_game');if(g.debt<0||g.inventory<0||g.soldTotal<0)fail(400,'invalid_game');if(g.finished&&g.turn!==20)fail(400,'invalid_finish');if(old){if(g.runId!==old.runId)fail(409,'different_campaign');if(g.turn<old.turn||g.turn>old.turn+1)fail(409,'invalid_turn');if((old.finished||old.bankrupt)&&(!g.finished&&!g.bankrupt))fail(409,'campaign_closed');if(old.quarterClosed&&g.turn===old.turn&&!g.quarterClosed)fail(409,'quarter_already_closed');}else if(g.turn!==1)fail(400,'new_campaign_must_start_at_one');}
function summary(g){const regs=Object.values(g.map?.regions||{}),branches=regs.filter(x=>x.branch>0).length,infl=regs.length?regs.reduce((a,x)=>a+(x.influence||0),0)/regs.length:0;const status=g.bankrupt?'bankrupt':g.finished?'finished':'active';let score=g.stage*900+Math.min(1600,g.totalRevenue/6500)+Math.min(1400,g.soldTotal*1.1)+g.awareness*8+g.cult*7+g.loyalty*5+g.international*4+g.marketShare*22+branches*130+infl*4+Math.min(800,Math.max(0,g.cash)/5000)-Math.min(900,g.debt/5000);if(status==='finished')score+=800;if(status==='bankrupt')score*=.62;return {status,turn:g.turn,stage:g.stage,score:Math.max(0,Math.round(score)),cash:g.cash,debt:g.debt,total_revenue:g.totalRevenue,sold_total:g.soldTotal,branch_count:branches,international:g.international,game_version:'9.0',lastProfit:g.lastProfit};}
async function cloud(tx,p,m){const s=await tx.get('save:'+p.id);return s&&s.epoch===m.epoch?s:{epoch:m.epoch,revision:0,payload:{game:null,ui:{}},updatedAt:null};}
async function saveRecord(tx,p,m,c,game,ui){c.revision++;c.epoch=m.epoch;c.payload={game,ui:ui||{}};c.updatedAt=now();await tx.set('save:'+p.id,c);let unlocked=[];
 if(game){const sum=summary(game),prev=await tx.get('run:'+game.runId);if(prev&&prev.player_id!==p.id)fail(403,'not_your_campaign');await tx.set('run:'+game.runId,{...prev,...sum,id:game.runId,player_id:p.id,nickname:p.nickname,epoch:m.epoch,updated_at:now(),started_at:prev?.started_at||now(),excluded:prev?.excluded||false,data:{inventory:game.inventory,chronicles:game.chronicles,team:Object.keys(game.team).filter(x=>game.team[x].active)}});const a=await tx.get('ach:'+p.id)||{};const merged=Ach.merge(a,game,now());await tx.set('ach:'+p.id,merged.records);unlocked=merged.unlocked;}
 await bump(tx,m);return {ok:true,epoch:m.epoch,revision:c.revision,updatedAt:c.updatedAt,unlocked,score:game?summary(game).score:0};}
async function checkedCloud(tx,p,m,b){const c=await cloud(tx,p,m);if(b.epoch!==m.epoch)fail(409,'season_changed',{epoch:m.epoch});if(b.revision!==c.revision)fail(409,'save_conflict',{revision:c.revision});return c;}
async function replay(tx,p,b,tag){if(!/^[\w-]{12,100}$/.test(String(b.requestId||'')))fail(400,'request_id_required');const key='op:'+p.id+':'+b.requestId;const old=await tx.get(key),digest=sha(JSON.stringify({tag,...b}));if(old){if(old.digest!==digest)fail(409,'request_reused');return {result:old.result,key,digest};}return {key,digest};}
async function leaders(tx,m){const rr=(await tx.scan('run:')).map(x=>x.value).filter(r=>r.epoch===m.epoch&&!r.excluded&&['finished','bankrupt'].includes(r.status));const best=new Map();for(const r of rr){const cur=best.get(r.player_id);if(!cur||r.score>cur.score)best.set(r.player_id,r);}return [...best.values()].sort((a,b)=>b.score-a.score||a.updated_at.localeCompare(b.updated_at)).slice(0,100).map((r,i)=>({rank:i+1,nickname:r.nickname,score:r.score,status:r.status,stage:r.stage,turn:r.turn,cash:r.cash}));}
async function exportData(tx){const all=await tx.scan('');return {format:'xbost-backup-v9',createdAt:now(),records:all.filter(x=>!['session:','transfer:','rate:','backup:','reset:','op:'].some(p=>x.key.startsWith(p)))};}
async function route(req,res,url,b){return store.transaction(async tx=>{
 const m=await meta(tx),p=url.pathname,method=req.method;
 if(p==='/api/health'&&method==='GET')return {ok:true,version:'9.0.0',db:store.kind};
 if(p==='/api/session'&&method==='GET'){const s=await session(tx,req,res,true);return s?{authenticated:true,user:s.role==='player'?publicUser(s.player):{role:'founder',name:'Основатель'},csrf:s.csrf,epoch:m.epoch}:{authenticated:false,version:'9.0.0'};}
 if(p==='/api/auth/register'&&method==='POST'){
  if(!await rate(tx,req,'register',10,3600000))return {httpStatus:429,error:'too_many_attempts'};const n=cleanNick(b.nickname);if(await tx.get('nick:'+n.norm))return {httpStatus:409,error:'nickname_taken'};
  const rc=code(),user={id:crypto.randomUUID(),nickname:n.nick,norm:n.norm,recoveryHash:sha(normCode(rc)),authVersion:1,tutorial:{step:0,complete:false},legacy:false,createdAt:now(),lastSeen:now()};await tx.set('player:'+user.id,user);await tx.set('nick:'+n.norm,{id:user.id});const s=await issueSession(tx,res,'player',user);await bump(tx,m);return {user:publicUser(user),csrf:s.csrf,recoveryCode:rc,epoch:m.epoch};
 }
 if(p==='/api/auth/recover'&&method==='POST'){
  if(!await rate(tx,req,'recover',8,900000))return {httpStatus:429,error:'too_many_attempts'};const n=cleanNick(b.nickname),ix=await tx.get('nick:'+n.norm),user=ix?await tx.get('player:'+ix.id):null;
  if(!user?.recoveryHash||!normCode(b.code)||user.recoveryHash!==sha(normCode(b.code)))return {httpStatus:401,error:'recovery_failed'};
  const rc=code();user.recoveryHash=sha(normCode(rc));user.authVersion++;user.legacy=false;user.lastSeen=now();await tx.set('player:'+user.id,user);const s=await issueSession(tx,res,'player',user);await bump(tx,m);return {user:publicUser(user),csrf:s.csrf,recoveryCode:rc,epoch:m.epoch};
 }
 if(p==='/api/auth/transfer'&&method==='POST'){
  if(!await rate(tx,req,'transfer',12,900000))return {httpStatus:429,error:'too_many_attempts'};const n=cleanNick(b.nickname),k='transfer:'+sha(normCode(b.code)),entry=await tx.get(k);const ix=await tx.get('nick:'+n.norm);if(!entry||!ix||ix.id!==entry.id||entry.until<Date.now())return {httpStatus:401,error:'transfer_failed'};const user=await tx.get('player:'+ix.id);if(entry.authVersion!==user.authVersion)return {httpStatus:401,error:'transfer_failed'};await tx.del(k);const s=await issueSession(tx,res,'player',user);return {user:publicUser(user),csrf:s.csrf,epoch:m.epoch};
 }
 if(p==='/api/login/founder'&&method==='POST'){
  if(!await rate(tx,req,'founder',6,900000))return {httpStatus:429,error:'too_many_attempts'};if(!await verifyPassword(b.password,FOUNDER_HASH))return {httpStatus:401,error:'bad_password'};const s=await issueSession(tx,res,'founder');return {user:{role:'founder',name:'Основатель'},csrf:s.csrf,epoch:m.epoch};
 }
 if(['/api/login/player','/api/progress','/api/result'].includes(p))return {httpStatus:426,error:'update_required'};
 if(p==='/api/logout'&&method==='POST'){await required(tx,req,res,null,true);await tx.del('session:'+sha(parseCookie(req)));cookie(res,'',0);return {ok:true};}
 if(p==='/api/profile/recovery'&&method==='POST'){const s=await required(tx,req,res,'player',true),user=s.player,rc=code();user.recoveryHash=sha(normCode(rc));user.legacy=false;await tx.set('player:'+user.id,user);await bump(tx,m);return {recoveryCode:rc};}
 if(p==='/api/profile/transfer'&&method==='POST'){const s=await required(tx,req,res,'player',true),rc=code();await tx.set('transfer:'+sha(normCode(rc)),{id:s.playerId,authVersion:s.player.authVersion,until:Date.now()+600000});return {transferCode:rc,expiresIn:600};}
 if(p==='/api/profile/tutorial'&&method==='PUT'){const s=await required(tx,req,res,'player',true);const t=b.tutorial;if(!t||!Number.isInteger(t.step)||t.step<0||t.step>50)fail(400,'bad_tutorial');s.player.tutorial=clone(t);await tx.set('player:'+s.playerId,s.player);await bump(tx,m);return {ok:true};}
 if(p==='/api/cloud'&&method==='GET'){const s=await required(tx,req,res,'player');return {...await cloud(tx,s.player,m),achievements:await tx.get('ach:'+s.playerId)||{},tutorial:s.player.tutorial};}
 if(p==='/api/cloud'&&method==='PUT'){
  const s=await required(tx,req,res,'player',true);if(b.protocol!==9)return {httpStatus:426,error:'update_required'};const rr=await replay(tx,s.player,b,p);if(rr.result)return rr.result;
  const c=await checkedCloud(tx,s.player,m,b),game=b.payload?.game;validateGame(game,c.payload.game);if(!game)fail(400,'game_required');if(JSON.stringify(b.payload).length>2200000)fail(413,'save_too_large');
  const result=await saveRecord(tx,s.player,m,c,game,b.payload.ui);await tx.set(rr.key,{digest:rr.digest,result});return result;
 }
 if(p==='/api/campaigns/abandon'&&method==='POST'){
  const s=await required(tx,req,res,'player',true),rr=await replay(tx,s.player,b,p);if(rr.result)return rr.result;const c=await checkedCloud(tx,s.player,m,b);if(c.payload.game){const r=await tx.get('run:'+c.payload.game.runId);if(r&&r.status==='active'){r.status='abandoned';await tx.set('run:'+r.id,r);}}
  const result=await saveRecord(tx,s.player,m,c,null,{});await tx.set(rr.key,{digest:rr.digest,result});return result;
 }
 if(p==='/api/dodep'&&method==='POST'){
  const s=await required(tx,req,res,'player',true),rr=await replay(tx,s.player,b,p);if(rr.result)return rr.result;const c=await checkedCloud(tx,s.player,m,b),g=c.payload.game;
  if(!g||g.finished||g.bankrupt||g.quarterClosed||g.specialPopup||g.liveSession||!g.team?.dmitry?.active||g.team.dmitry.cooldown>0||g.v9PendingDodep)fail(409,'ability_unavailable');
  const r=crypto.randomInt(1000000)/1000000,gain=250000+g.stage*12000,loss=120000+g.stage*12000,crash=160000+g.stage*18000;
  const kind=r<.52?'gain':r<.9?'loss':'crash',delta=kind==='gain'?gain:kind==='loss'?-loss:-crash;
  if(g.cash<Math.max(loss,crash))fail(409,'not_enough_for_risk');const before=g.cash;g.cash+=delta;g.team.dmitry.cooldown=2;if(kind==='crash')g.flags.financeShock=Math.max(g.flags.financeShock||0,1);
  const angle=kind==='gain'?crypto.randomInt(15,Math.floor(360*.52)-15):crypto.randomInt(Math.ceil(360*.52)+15,345);
  g.v9PendingDodep={id:b.requestId,kind,delta,before,probability:52,angle,turn:g.turn};g.v9metrics=g.v9metrics||{};g.v9metrics.specials=(g.v9metrics.specials||0)+1;
  const title=kind==='gain'?'ДОДЕП СРАБОТАЛ':kind==='crash'?'ДОДЕП ПРОБИЛ ПОДДЕРЖКУ':'ДОДЕП НЕ СРАБОТАЛ';g.news.unshift({turn:g.turn,title,text:'Инвестиционная операция Дмитрия: '+(delta>0?'+':'')+delta.toLocaleString('ru-RU')+' ₽.',kind:'normal'});g.news=g.news.slice(0,120);g.qlog.staff.push('ДОДЕП: '+(delta>0?'+':'')+delta+' ₽.');
  const result=await saveRecord(tx,s.player,m,c,g,c.payload.ui);result.payload=c.payload;await tx.set(rr.key,{digest:rr.digest,result});return result;
 }
 if(p==='/api/achievements'&&method==='GET'){const s=await required(tx,req,res,'player');return {definitions:Ach.definitions,records:await tx.get('ach:'+s.playerId)||{}};}
 if(p==='/api/leaderboard'&&method==='GET'){await required(tx,req,res);return {epoch:m.epoch,rows:await leaders(tx,m)};}
 if(p==='/api/founder/overview'&&method==='GET'){
  await required(tx,req,res,'founder');const users=(await tx.scan('player:')).map(x=>x.value),runs=(await tx.scan('run:')).map(x=>x.value).sort((a,b)=>b.updated_at.localeCompare(a.updated_at));return {epoch:m.epoch,players:users.map(x=>({id:x.id,nickname:x.nickname,created_at:x.createdAt,last_seen:x.lastSeen,needsRecovery:!x.recoveryHash})),runs,leaderboard:await leaders(tx,m),legacyRuns:(await tx.scan('legacyrun:')).length};
 }
 let match=p.match(/^\/api\/founder\/runs\/([\w-]+)\/exclude$/);
 if(match&&method==='POST'){await required(tx,req,res,'founder',true);const r=await tx.get('run:'+match[1]);if(!r)fail(404,'not_found');r.excluded=!!b.excluded;await tx.set('run:'+r.id,r);await bump(tx,m);return {ok:true};}
 match=p.match(/^\/api\/founder\/players\/([\w-]+)\/recovery$/);
 if(match&&method==='POST'){await required(tx,req,res,'founder',true);if(b.confirm!=='ЛИЧНОСТЬ ПОДТВЕРЖДЕНА')fail(400,'confirmation_required');const p=await tx.get('player:'+match[1]);if(!p)fail(404,'not_found');const rc=code();p.recoveryHash=sha(normCode(rc));p.authVersion++;p.legacy=false;await tx.set('player:'+p.id,p);await bump(tx,m);await tx.set('audit:'+crypto.randomUUID(),{action:'founder-recovery',player:p.id,at:now()});return {recoveryCode:rc,nickname:p.nickname};}
 if(p==='/api/founder/export'&&method==='GET'){await required(tx,req,res,'founder');return {download:'xbost-backup-'+Date.now()+'.json',data:await exportData(tx)};}
 if(p==='/api/founder/reset/prepare'&&method==='POST'){
  await required(tx,req,res,'founder',true);const data=await exportData(tx),id=crypto.randomUUID(),receipt=random();await tx.set('backup:'+id,{data,at:now()});await tx.set('reset:'+sha(receipt),{id,revision:m.dataRevision,until:Date.now()+600000});return {receipt,backupId:id,counts:{runs:(await tx.scan('run:')).length,legacy:(await tx.scan('legacyrun:')).length,saves:(await tx.scan('save:')).length},data};
 }
 if(p==='/api/founder/reset/confirm'&&method==='POST'){
  await required(tx,req,res,'founder',true);const r=await tx.get('reset:'+sha(b.receipt));if(!r||r.until<Date.now()||b.confirm!=='ОЧИСТИТЬ ПРОХОЖДЕНИЯ')fail(400,'confirmation_required');if(r.revision!==m.dataRevision)fail(409,'backup_outdated');if(!await tx.get('backup:'+r.id))fail(409,'backup_missing');
  for(const prefix of ['save:','run:','legacyrun:','op:'])for(const row of await tx.scan(prefix))await tx.del(row.key);await tx.clearLegacyRuns();m.epoch++;await bump(tx,m);await tx.del('reset:'+sha(b.receipt));await tx.set('audit:'+crypto.randomUUID(),{action:'reset-campaigns',at:now(),backupId:r.id,epoch:m.epoch});return {ok:true,epoch:m.epoch,backupId:r.id};
 }
 match=p.match(/^\/api\/founder\/backups\/([\w-]+)$/);
 if(match&&method==='GET'){await required(tx,req,res,'founder');const r=await tx.get('backup:'+match[1]);if(!r)fail(404,'not_found');return {download:'xbost-backup-'+match[1]+'.json',data:r.data};}
 if(p==='/api/founder/export.csv'&&method==='GET'){await required(tx,req,res,'founder');const r=(await tx.scan('run:')).map(x=>x.value);const esc=x=>'"'+String(x??'').replace(/^[=+@-]/,"'").replace(/"/g,'""')+'"';return {csv:'\uFEFF'+[['Ник','Индекс','Статус','Квартал','Касса','Выручка'],...r.map(x=>[x.nickname,x.score,x.status,x.turn,x.cash,x.total_revenue])].map(a=>a.map(esc).join(',')).join('\r\n')};}
 fail(404,'not_found');
});}
async function serve(req,res){securityHeaders(res);try{const url=new URL(req.url,'http://localhost');if(url.pathname.startsWith('/api/')){originCheck(req);const b=['POST','PUT','PATCH'].includes(req.method)?await body(req):{};const result=await route(req,res,url,b);if(result.download){res.setHeader('Content-Disposition','attachment; filename="'+result.download+'"');return send(res,200,result.data);}if(result.csv){res.setHeader('Content-Disposition','attachment; filename="xbost-results.csv"');return send(res,200,result.csv,'text/csv; charset=utf-8');}return send(res,result.httpStatus||200,result);}
 if(!['GET','HEAD'].includes(req.method))return send(res,405,{error:'method_not_allowed'});
 if(url.pathname==='/sw.js')return send(res,200,"self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>/xbost/i.test(k)).map(k=>caches.delete(k)))).then(()=>self.registration.unregister())));",'application/javascript; charset=utf-8');
 if(!['/','/index.html'].includes(url.pathname))return send(res,404,'Not found','text/plain');
 let html;try{html=await fs.readFile(path.join(PUBLIC,'index.html'));}catch(e){if(e.code!=='ENOENT')throw e;html=await fs.readFile(path.join(__dirname,'index.html'));}res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Length':html.length});res.end(req.method==='HEAD'?undefined:html);
 }catch(e){if(e.status)return send(res,e.status,{error:e.error,...(e.revision!==undefined?{revision:e.revision}:{}),...(e.epoch!==undefined?{epoch:e.epoch}:{})});console.error('XBOST request failed:',e.code||e.message);if(!res.headersSent)send(res,500,{error:'server_error'});else res.end();}}
async function main(){await store.init();await store.transaction(async tx=>{await meta(tx);});const server=http.createServer(serve);server.requestTimeout=30000;server.headersTimeout=15000;server.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('XBOST v9 server ready; storage='+store.kind));const shutdown=()=>server.close(()=>store.close().then(()=>process.exit(0)));process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);}
if(require.main===module)main().catch(e=>{console.error('Startup failed:',e.message);process.exit(1);});
module.exports={serve,store,verifyPassword,summary,validateGame};
