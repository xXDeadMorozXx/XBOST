'use strict';
// Small transactional document store. Postgres is mandatory in production.
// One advisory lock serializes mutations; only touched documents are written.
const fs = require('node:fs/promises');
const path = require('node:path');
const copy = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
class FileStore {
  constructor(file) { this.file=file; this.rows={}; this.tail=Promise.resolve(); this.kind='file-development'; }
  async init() { try { this.rows=JSON.parse(await fs.readFile(this.file,'utf8')); } catch(e) { if(e.code!=='ENOENT') throw e; } }
  transaction(fn) {
    const job=this.tail.then(async()=>{
      const rows=copy(this.rows);
      const tx={get:async k=>copy(rows[k])||null,set:async(k,v)=>{rows[k]=copy(v);},del:async k=>{delete rows[k];},scan:async prefix=>Object.entries(rows).filter(([k])=>k.startsWith(prefix)).map(([key,value])=>({key,value:copy(value)})),clearLegacyRuns:async()=>{}};
      const result=await fn(tx);
      await fs.mkdir(path.dirname(this.file),{recursive:true});
      await fs.writeFile(this.file+'.tmp',JSON.stringify(rows),{mode:0o600});await fs.rename(this.file+'.tmp',this.file);this.rows=rows;return result;
    }); this.tail=job.catch(()=>{});return job;
  }
  async close() { await this.tail; }
}
class PgStore {
  constructor(url) {
    const {Pool}=require('pg');const u=new URL(url);const internal=u.hostname==='localhost'||u.hostname==='127.0.0.1'||(!u.hostname.includes('.'))||u.hostname.endsWith('.internal');
    const cfg={connectionString:url,max:5,connectionTimeoutMillis:12000,idleTimeoutMillis:30000};
    if(!u.searchParams.has('sslmode'))cfg.ssl=process.env.DATABASE_SSL==='disable'||internal?false:{rejectUnauthorized:true};
    this.pool=new Pool(cfg);this.kind='postgres';
  }
  async init() {
    await this.pool.query('CREATE TABLE IF NOT EXISTS xbost_v9_records (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())');
    // Additive migration: preserve v8 profiles. Never claim an existing nickname without proof.
    const client=await this.pool.connect();
    try { await client.query('BEGIN');await client.query('SELECT pg_advisory_xact_lock(986734091)');
      const done=await client.query("SELECT 1 FROM xbost_v9_records WHERE key='migration:v8'");
      if(!done.rowCount){
        const exists=await client.query("SELECT to_regclass('public.xbost_players') AS name");
        if(exists.rows[0].name){
          const old=await client.query('SELECT id,nickname,nickname_norm,created_at,last_seen FROM xbost_players');
          for(const p of old.rows){const user={id:p.id,nickname:p.nickname,norm:p.nickname_norm,recoveryHash:null,authVersion:1,tutorial:{step:0},legacy:true,createdAt:p.created_at,lastSeen:p.last_seen};
            await client.query('INSERT INTO xbost_v9_records(key,value) VALUES($1,$2) ON CONFLICT DO NOTHING',['player:'+p.id,JSON.stringify(user)]);
            await client.query('INSERT INTO xbost_v9_records(key,value) VALUES($1,$2) ON CONFLICT DO NOTHING',['nick:'+p.nickname_norm,JSON.stringify({id:p.id})]);
          }
        }
        const runs=await client.query("SELECT to_regclass('public.xbost_runs') AS name");
        if(runs.rows[0].name){const old=await client.query('SELECT * FROM xbost_runs');for(const r of old.rows)await client.query('INSERT INTO xbost_v9_records(key,value) VALUES($1,$2) ON CONFLICT DO NOTHING',['legacyrun:'+r.id,JSON.stringify(r)]);}
        await client.query("INSERT INTO xbost_v9_records(key,value) VALUES('migration:v8',$1)",[JSON.stringify({at:new Date().toISOString()})]);
      }
      await client.query('COMMIT');
    }catch(e){await client.query('ROLLBACK');throw e;}finally{client.release();}
  }
  async transaction(fn) {
    const c=await this.pool.connect();
    try {await c.query('BEGIN');await c.query('SET LOCAL statement_timeout = 15000');await c.query('SELECT pg_advisory_xact_lock(986734091)');
      const tx={
        get:async key=>{const q=await c.query('SELECT value FROM xbost_v9_records WHERE key=$1',[key]);return q.rows[0]?.value||null;},
        set:async(key,v)=>{await c.query('INSERT INTO xbost_v9_records(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()',[key,JSON.stringify(v)]);},
        del:async key=>{await c.query('DELETE FROM xbost_v9_records WHERE key=$1',[key]);},
        scan:async prefix=>{const q=await c.query('SELECT key,value FROM xbost_v9_records WHERE left(key,$1)=$2 ORDER BY key',[prefix.length,prefix]);return q.rows;},
        clearLegacyRuns:async()=>{const q=await c.query("SELECT to_regclass('public.xbost_runs') AS name");if(q.rows[0].name)await c.query('DELETE FROM xbost_runs');}
      };
      const out=await fn(tx);await c.query('COMMIT');return out;
    }catch(e){await c.query('ROLLBACK');throw e;}finally{c.release();}
  }
  async close(){await this.pool.end();}
}
function createStore(){if(process.env.DATABASE_URL)return new PgStore(process.env.DATABASE_URL);if(process.env.NODE_ENV==='production')throw Error('DATABASE_URL is required; no volatile database in production');if(!process.env.DEV_DATA_FILE)throw Error('For local testing set DEV_DATA_FILE to a private JSON path');return new FileStore(process.env.DEV_DATA_FILE);}
module.exports={FileStore,PgStore,createStore};
