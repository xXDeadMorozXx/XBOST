'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = path.join(__dirname, 'public');
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const PLAYER_PASSWORD_HASH = process.env.PLAYER_PASSWORD_HASH || '';
const FOUNDER_PASSWORD_HASH = process.env.FOUNDER_PASSWORD_HASH || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const ALLOW_MEMORY_DB = process.env.ALLOW_MEMORY_DB === '1' || !DATABASE_URL;
const COOKIE_NAME = 'xbost_session';
const GAME_VERSION = '8.0';

if (!SESSION_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('SESSION_SECRET is required in production');
}
if ((!PLAYER_PASSWORD_HASH || !FOUNDER_PASSWORD_HASH) && process.env.NODE_ENV === 'production') {
  throw new Error('PLAYER_PASSWORD_HASH and FOUNDER_PASSWORD_HASH are required in production');
}

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}
function fromB64url(input) {
  return Buffer.from(input, 'base64url').toString('utf8');
}
function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET || 'xbost-dev-secret').update(value).digest('base64url');
}
function createSession(payload) {
  const body = b64url(JSON.stringify(payload));
  return `${body}.${sign(body)}`;
}
function readSessionToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expected = sign(body);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  } catch (_) { return null; }
  try {
    const data = JSON.parse(fromB64url(body));
    if (!data.exp || Date.now() > data.exp) return null;
    return data;
  } catch (_) { return null; }
}
function cookieMap(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}
function sessionFromReq(req) {
  return readSessionToken(cookieMap(req)[COOKIE_NAME]);
}
function setSession(res, payload) {
  const token = createSession(payload);
  const maxAge = 60 * 60 * 24 * 365;
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly${secure}; SameSite=Lax; Max-Age=${maxAge}`);
}
function clearSession(res) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly${secure}; SameSite=Lax; Max-Age=0`);
}
function json(res, status, body) {
  const data = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': data.length,
    'Cache-Control': 'no-store'
  });
  res.end(data);
}
function text(res, status, body, contentType='text/plain; charset=utf-8') {
  const data = Buffer.from(body);
  res.writeHead(status, {'Content-Type': contentType, 'Content-Length': data.length, 'Cache-Control':'no-store'});
  res.end(data);
}
async function readJson(req, max=65536) {
  return await new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', c => {
      total += c.length;
      if (total > max) { reject(new Error('payload_too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (_) { reject(new Error('invalid_json')); }
    });
    req.on('error', reject);
  });
}

function parsePasswordHash(encoded) {
  const [scheme, saltB64, hashB64] = String(encoded || '').split('$');
  if (scheme !== 'scrypt' || !saltB64 || !hashB64) return null;
  return { salt: Buffer.from(saltB64, 'base64url'), hash: Buffer.from(hashB64, 'base64url') };
}
function verifyPassword(password, encoded) {
  const p = parsePasswordHash(encoded);
  if (!p) return false;
  const got = crypto.scryptSync(String(password || ''), p.salt, p.hash.length);
  return got.length === p.hash.length && crypto.timingSafeEqual(got, p.hash);
}

const attempts = new Map();
function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (Array.isArray(xf) ? xf[0] : String(xf || '').split(',')[0]).trim() || req.socket.remoteAddress || 'unknown';
}
function rateAllowed(req, bucket, max, windowMs) {
  const key = `${bucket}:${clientIp(req)}`;
  const now = Date.now();
  const row = attempts.get(key) || {start: now, count: 0};
  if (now - row.start > windowMs) { row.start = now; row.count = 0; }
  row.count++;
  attempts.set(key, row);
  return row.count <= max;
}

function safeNickname(raw) {
  const nick = String(raw || '').trim().replace(/\s+/g, ' ');
  if (nick.length < 2 || nick.length > 24) return null;
  if (!/^[\p{L}\p{N}_.\- ]+$/u.test(nick)) return null;
  const norm = nick.toLocaleLowerCase('ru-RU');
  const reserved = ['admin','founder','основатель','xbost','щищ','system','система'];
  if (reserved.includes(norm)) return null;
  return {nick, norm};
}
function clampNum(x, min, max) {
  x = Number(x);
  if (!Number.isFinite(x)) return min;
  return Math.max(min, Math.min(max, x));
}
function cleanRunBody(body) {
  const status = ['active','finished','bankrupt','abandoned'].includes(body.status) ? body.status : 'active';
  return {
    runId: String(body.runId || '').slice(0, 80),
    status,
    turn: Math.round(clampNum(body.turn, 1, 20)),
    stage: Math.round(clampNum(body.stage, 0, 4)),
    cash: Math.round(clampNum(body.cash, -5000000, 50000000)),
    debt: Math.round(clampNum(body.debt, 0, 50000000)),
    totalRevenue: Math.round(clampNum(body.totalRevenue, 0, 100000000)),
    soldTotal: Math.round(clampNum(body.soldTotal, 0, 100000)),
    awareness: clampNum(body.awareness, 0, 100),
    hype: clampNum(body.hype, 0, 100),
    loyalty: clampNum(body.loyalty, 0, 100),
    cult: clampNum(body.cult, 0, 100),
    international: clampNum(body.international, 0, 100),
    marketShare: clampNum(body.marketShare, 0, 45),
    branchCount: Math.round(clampNum(body.branchCount, 0, 30)),
    mapInfluence: clampNum(body.mapInfluence, 0, 100),
    version: String(body.version || GAME_VERSION).slice(0, 20),
    snapshot: body.snapshot && typeof body.snapshot === 'object' ? body.snapshot : {}
  };
}
function scoreRun(r) {
  let score = 0;
  score += r.stage * 900;
  score += Math.min(1600, r.totalRevenue / 6500);
  score += Math.min(1400, r.soldTotal * 1.1);
  score += r.awareness * 8;
  score += r.cult * 7;
  score += r.loyalty * 5;
  score += r.international * 4;
  score += r.marketShare * 22;
  score += r.branchCount * 130;
  score += r.mapInfluence * 4;
  score += Math.min(800, Math.max(0, r.cash) / 5000);
  score -= Math.min(900, r.debt / 5000);
  if (r.status === 'finished') score += 800;
  if (r.status === 'bankrupt') score *= 0.62;
  if (r.status === 'abandoned') score *= 0.35;
  return Math.max(0, Math.round(score));
}

class MemoryStore {
  constructor(){ this.players = new Map(); this.nick = new Map(); this.runs = new Map(); }
  async init(){}
  async getPlayer(id){ return this.players.get(id) || null; }
  async getPlayerByNorm(norm){ const id=this.nick.get(norm); return id?this.players.get(id):null; }
  async createPlayer(nickname,norm){
    const p={id:crypto.randomUUID(),nickname,nickname_norm:norm,created_at:new Date().toISOString(),last_seen:new Date().toISOString()};
    this.players.set(p.id,p); this.nick.set(norm,p.id); return p;
  }
  async touchPlayer(id){ const p=this.players.get(id); if(p)p.last_seen=new Date().toISOString(); }
  async upsertRun(playerId, r){
    const prev=this.runs.get(r.runId)||{};
    const row={...prev,id:r.runId,player_id:playerId,game_version:r.version,status:r.status,turn:r.turn,stage:r.stage,score:scoreRun(r),cash:r.cash,debt:r.debt,total_revenue:r.totalRevenue,sold_total:r.soldTotal,awareness:r.awareness,hype:r.hype,loyalty:r.loyalty,cult:r.cult,international:r.international,market_share:r.marketShare,branch_count:r.branchCount,map_influence:r.mapInfluence,data:r.snapshot,started_at:prev.started_at||new Date().toISOString(),updated_at:new Date().toISOString(),finished_at:['finished','bankrupt','abandoned'].includes(r.status)?new Date().toISOString():null,excluded:prev.excluded||false};
    this.runs.set(r.runId,row); return row;
  }
  async leaderboard(){
    const finals=[...this.runs.values()].filter(r=>['finished','bankrupt'].includes(r.status)&&!r.excluded);
    const best=new Map();
    for(const r of finals){ const cur=best.get(r.player_id); if(!cur||r.score>cur.score)best.set(r.player_id,r); }
    return [...best.values()].sort((a,b)=>b.score-a.score).slice(0,100).map((r,i)=>({rank:i+1,nickname:this.players.get(r.player_id)?.nickname||'?',score:r.score,status:r.status,stage:r.stage,turn:r.turn,cash:r.cash,totalRevenue:r.total_revenue,soldTotal:r.sold_total,branchCount:r.branch_count,updatedAt:r.updated_at}));
  }
  async founderOverview(){
    const players=[...this.players.values()].sort((a,b)=>new Date(b.last_seen)-new Date(a.last_seen));
    const runs=[...this.runs.values()].sort((a,b)=>new Date(b.updated_at)-new Date(a.updated_at));
    return {players,runs,leaderboard:await this.leaderboard()};
  }
  async setExcluded(runId,excluded){ const r=this.runs.get(runId); if(!r)return null;r.excluded=!!excluded;return r; }
}

class PgStore {
  constructor(url){ const {Pool}=require('pg'); this.pool=new Pool({connectionString:url,ssl:{rejectUnauthorized:false}}); }
  async init(){
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS xbost_players(
        id TEXT PRIMARY KEY,
        nickname TEXT NOT NULL,
        nickname_norm TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS xbost_runs(
        id TEXT PRIMARY KEY,
        player_id TEXT NOT NULL REFERENCES xbost_players(id) ON DELETE CASCADE,
        game_version TEXT NOT NULL,
        status TEXT NOT NULL,
        turn INTEGER NOT NULL,
        stage INTEGER NOT NULL,
        score INTEGER NOT NULL DEFAULT 0,
        cash BIGINT NOT NULL DEFAULT 0,
        debt BIGINT NOT NULL DEFAULT 0,
        total_revenue BIGINT NOT NULL DEFAULT 0,
        sold_total INTEGER NOT NULL DEFAULT 0,
        awareness DOUBLE PRECISION NOT NULL DEFAULT 0,
        hype DOUBLE PRECISION NOT NULL DEFAULT 0,
        loyalty DOUBLE PRECISION NOT NULL DEFAULT 0,
        cult DOUBLE PRECISION NOT NULL DEFAULT 0,
        international DOUBLE PRECISION NOT NULL DEFAULT 0,
        market_share DOUBLE PRECISION NOT NULL DEFAULT 0,
        branch_count INTEGER NOT NULL DEFAULT 0,
        map_influence DOUBLE PRECISION NOT NULL DEFAULT 0,
        data JSONB NOT NULL DEFAULT '{}'::jsonb,
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        finished_at TIMESTAMPTZ,
        excluded BOOLEAN NOT NULL DEFAULT FALSE
      );
      CREATE INDEX IF NOT EXISTS xbost_runs_player_idx ON xbost_runs(player_id);
      CREATE INDEX IF NOT EXISTS xbost_runs_score_idx ON xbost_runs(score DESC);
    `);
  }
  async getPlayer(id){ const q=await this.pool.query('SELECT * FROM xbost_players WHERE id=$1',[id]); return q.rows[0]||null; }
  async getPlayerByNorm(norm){ const q=await this.pool.query('SELECT * FROM xbost_players WHERE nickname_norm=$1',[norm]); return q.rows[0]||null; }
  async createPlayer(nickname,norm){
    const id=crypto.randomUUID();
    const q=await this.pool.query('INSERT INTO xbost_players(id,nickname,nickname_norm) VALUES($1,$2,$3) RETURNING *',[id,nickname,norm]);return q.rows[0];
  }
  async touchPlayer(id){ await this.pool.query('UPDATE xbost_players SET last_seen=NOW() WHERE id=$1',[id]); }
  async upsertRun(playerId,r){
    const score=scoreRun(r), finished=['finished','bankrupt','abandoned'].includes(r.status);
    const q=await this.pool.query(`
      INSERT INTO xbost_runs(id,player_id,game_version,status,turn,stage,score,cash,debt,total_revenue,sold_total,awareness,hype,loyalty,cult,international,market_share,branch_count,map_influence,data,finished_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
      ON CONFLICT(id) DO UPDATE SET
        status=EXCLUDED.status,turn=EXCLUDED.turn,stage=EXCLUDED.stage,score=EXCLUDED.score,cash=EXCLUDED.cash,debt=EXCLUDED.debt,total_revenue=EXCLUDED.total_revenue,sold_total=EXCLUDED.sold_total,awareness=EXCLUDED.awareness,hype=EXCLUDED.hype,loyalty=EXCLUDED.loyalty,cult=EXCLUDED.cult,international=EXCLUDED.international,market_share=EXCLUDED.market_share,branch_count=EXCLUDED.branch_count,map_influence=EXCLUDED.map_influence,data=EXCLUDED.data,updated_at=NOW(),finished_at=COALESCE(EXCLUDED.finished_at,xbost_runs.finished_at)
      RETURNING *`,
      [r.runId,playerId,r.version,r.status,r.turn,r.stage,score,r.cash,r.debt,r.totalRevenue,r.soldTotal,r.awareness,r.hype,r.loyalty,r.cult,r.international,r.marketShare,r.branchCount,r.mapInfluence,JSON.stringify(r.snapshot),finished?new Date():null]);
    return q.rows[0];
  }
  async leaderboard(){
    const q=await this.pool.query(`
      WITH ranked AS (
        SELECT r.*,p.nickname,ROW_NUMBER() OVER(PARTITION BY player_id ORDER BY score DESC, updated_at DESC) rn
        FROM xbost_runs r JOIN xbost_players p ON p.id=r.player_id
        WHERE r.status IN ('finished','bankrupt') AND r.excluded=FALSE
      )
      SELECT nickname,score,status,stage,turn,cash,total_revenue,sold_total,branch_count,updated_at
      FROM ranked WHERE rn=1 ORDER BY score DESC,updated_at ASC LIMIT 100`);
    return q.rows.map((r,i)=>({rank:i+1,nickname:r.nickname,score:r.score,status:r.status,stage:r.stage,turn:r.turn,cash:Number(r.cash),totalRevenue:Number(r.total_revenue),soldTotal:r.sold_total,branchCount:r.branch_count,updatedAt:r.updated_at}));
  }
  async founderOverview(){
    const [p,r,l]=await Promise.all([
      this.pool.query('SELECT id,nickname,created_at,last_seen FROM xbost_players ORDER BY last_seen DESC'),
      this.pool.query(`SELECT r.id,r.player_id,p.nickname,r.game_version,r.status,r.turn,r.stage,r.score,r.cash,r.debt,r.total_revenue,r.sold_total,r.awareness,r.hype,r.loyalty,r.cult,r.international,r.market_share,r.branch_count,r.map_influence,r.started_at,r.updated_at,r.finished_at,r.excluded,r.data FROM xbost_runs r JOIN xbost_players p ON p.id=r.player_id ORDER BY r.updated_at DESC LIMIT 500`),
      this.leaderboard()
    ]);
    return {players:p.rows,runs:r.rows,leaderboard:l};
  }
  async setExcluded(runId,excluded){ const q=await this.pool.query('UPDATE xbost_runs SET excluded=$2,updated_at=NOW() WHERE id=$1 RETURNING *',[runId,!!excluded]); return q.rows[0]||null; }
}

const store = DATABASE_URL ? new PgStore(DATABASE_URL) : new MemoryStore();

function requireRole(req,res,role){
  const s=sessionFromReq(req);
  if(!s || (role && s.role!==role)){ json(res,401,{error:'unauthorized'}); return null; }
  return s;
}
function mimeFor(file){
  const ext=path.extname(file).toLowerCase();
  return ({'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml','.json':'application/json; charset=utf-8','.ico':'image/x-icon'})[ext]||'application/octet-stream';
}
function serveStatic(req,res,url){
  let pathname=decodeURIComponent(url.pathname);
  if(pathname==='/'||pathname==='')pathname='/index.html';
  const file=path.normalize(path.join(PUBLIC_DIR,pathname));
  if(!file.startsWith(PUBLIC_DIR)){ text(res,403,'Forbidden');return; }
  fs.readFile(file,(err,data)=>{
    if(err){
      fs.readFile(path.join(PUBLIC_DIR,'index.html'),(e,fallback)=>{if(e)text(res,404,'Not found');else{res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache'});res.end(fallback);}});
      return;
    }
    const cache=path.basename(file)==='index.html'?'no-cache':'public, max-age=86400';
    res.writeHead(200,{'Content-Type':mimeFor(file),'Content-Length':data.length,'Cache-Control':cache});res.end(data);
  });
}
function csvEscape(v){ const s=String(v??''); return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s; }

async function handleApi(req,res,url){
  const method=req.method||'GET';
  if(method==='GET'&&url.pathname==='/api/health')return json(res,200,{ok:true,version:GAME_VERSION,db:DATABASE_URL?'postgres':'memory'});
  if(method==='GET'&&url.pathname==='/api/session'){
    const s=sessionFromReq(req);if(!s)return json(res,200,{authenticated:false});
    if(s.role==='founder')return json(res,200,{authenticated:true,user:{role:'founder',name:'Основатель'}});
    const p=await store.getPlayer(s.playerId);if(!p){clearSession(res);return json(res,200,{authenticated:false});}
    await store.touchPlayer(p.id);return json(res,200,{authenticated:true,user:{role:'player',id:p.id,nickname:p.nickname}});
  }
  if(method==='POST'&&url.pathname==='/api/login/player'){
    if(!rateAllowed(req,'player-login',12,15*60*1000))return json(res,429,{error:'too_many_attempts'});
    const body=await readJson(req);const n=safeNickname(body.nickname);
    if(!n)return json(res,400,{error:'bad_nickname'});
    if(!verifyPassword(body.password,PLAYER_PASSWORD_HASH))return json(res,401,{error:'bad_password'});
    let p=await store.getPlayerByNorm(n.norm);const existing=sessionFromReq(req);
    if(p){
      if(!existing||existing.role!=='player'||existing.playerId!==p.id)return json(res,409,{error:'nickname_taken'});
    }else p=await store.createPlayer(n.nick,n.norm);
    await store.touchPlayer(p.id);
    setSession(res,{role:'player',playerId:p.id,nickname:p.nickname,exp:Date.now()+365*24*60*60*1000});
    return json(res,200,{ok:true,user:{role:'player',id:p.id,nickname:p.nickname}});
  }
  if(method==='POST'&&url.pathname==='/api/login/founder'){
    if(!rateAllowed(req,'founder-login',6,15*60*1000))return json(res,429,{error:'too_many_attempts'});
    const body=await readJson(req);
    if(!verifyPassword(body.password,FOUNDER_PASSWORD_HASH))return json(res,401,{error:'bad_password'});
    setSession(res,{role:'founder',exp:Date.now()+30*24*60*60*1000});
    return json(res,200,{ok:true,user:{role:'founder',name:'Основатель'}});
  }
  if(method==='POST'&&url.pathname==='/api/logout'){clearSession(res);return json(res,200,{ok:true});}
  if(method==='GET'&&url.pathname==='/api/leaderboard'){
    const s=requireRole(req,res);if(!s)return;return json(res,200,{rows:await store.leaderboard()});
  }
  if(method==='POST'&&(url.pathname==='/api/progress'||url.pathname==='/api/result')){
    const s=requireRole(req,res,'player');if(!s)return;
    const body=cleanRunBody(await readJson(req));
    if(!body.runId)return json(res,400,{error:'missing_run_id'});
    if(url.pathname==='/api/result'&&!['finished','bankrupt','abandoned'].includes(body.status))body.status='finished';
    const row=await store.upsertRun(s.playerId,body);return json(res,200,{ok:true,score:row.score||scoreRun(body)});
  }
  if(method==='GET'&&url.pathname==='/api/founder/overview'){
    const s=requireRole(req,res,'founder');if(!s)return;return json(res,200,await store.founderOverview());
  }
  const ex=url.pathname.match(/^\/api\/founder\/runs\/([^/]+)\/exclude$/);
  if(method==='POST'&&ex){
    const s=requireRole(req,res,'founder');if(!s)return;const body=await readJson(req);const row=await store.setExcluded(decodeURIComponent(ex[1]),!!body.excluded);if(!row)return json(res,404,{error:'not_found'});return json(res,200,{ok:true});
  }
  if(method==='GET'&&url.pathname==='/api/founder/export.csv'){
    const s=requireRole(req,res,'founder');if(!s)return;const data=await store.founderOverview();
    const head=['nickname','run_id','status','version','turn','stage','score','cash','debt','revenue','sold','awareness','hype','loyalty','cult','international','market_share','branches','map_influence','excluded','updated_at'];
    const rows=[head.join(',')];
    data.runs.forEach(r=>rows.push([r.nickname,r.id,r.status,r.game_version,r.turn,r.stage,r.score,r.cash,r.debt,r.total_revenue,r.sold_total,r.awareness,r.hype,r.loyalty,r.cult,r.international,r.market_share,r.branch_count,r.map_influence,r.excluded,r.updated_at].map(csvEscape).join(',')));
    const body=rows.join('\n');res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="xbost-results.csv"','Cache-Control':'no-store'});return res.end(body);
  }
  return json(res,404,{error:'not_found'});
}

async function main(){
  await store.init();
  const server=http.createServer(async(req,res)=>{
    try{
      const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
      if(url.pathname.startsWith('/api/'))await handleApi(req,res,url);else serveStatic(req,res,url);
    }catch(err){console.error(err);if(!res.headersSent)json(res,500,{error:'server_error'});else res.end();}
  });
  server.listen(PORT,()=>console.log(`XBOST v8 server listening on ${PORT}`));
}
main().catch(err=>{console.error(err);process.exit(1)});
