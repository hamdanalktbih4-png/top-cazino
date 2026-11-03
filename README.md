#!/usr/bin/env bash
# topcazino-deploy.sh — نشر TOPCAZINO كامل بأمر واحد
# Ubuntu/Debian · root · ينشئ /opt/topcazino + systemd + nginx + TLS
set -euo pipefail

APP=topcazino
DIR=/opt/$APP
DOMAIN="${1:-}"
EMAIL="${2:-}"
NODE_MIN=22

log(){ printf '\033[1;33m▸ %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31m✗ %s\033[0m\n' "$*"; exit 1; }

[ "$(id -u)" = 0 ] || die "شغّله كـ root"
[ -n "$DOMAIN" ] || die "الاستخدام: ./topcazino-deploy.sh example.com admin@example.com"

log "تثبيت المتطلبات"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates nginx certbot python3-certbot-nginx ufw sqlite3 openssl >/dev/null

if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt $NODE_MIN ]; then
  log "تثبيت Node.js $NODE_MIN"
  curl -fsSL https://deb.nodesource.com/setup_${NODE_MIN}.x | bash - >/dev/null 2>&1
  apt-get install -y -qq nodejs >/dev/null
fi
node -v

id -u $APP >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d $DIR $APP
mkdir -p $DIR/{views,public,locales,scripts,deploy,data,logs}

log "كتابة المشروع"

cat > $DIR/package.json <<'EOF'
{ "name":"topcazino","version":"1.0.0","private":true,"type":"commonjs","engines":{"node":">=22"},"scripts":{"start":"node --experimental-sqlite server.js"} }
EOF

cat > $DIR/.env <<EOF
NODE_ENV=production
PORT=3000
HOST=127.0.0.1
PUBLIC_URL=https://$DOMAIN
APP_SECRET=$(openssl rand -hex 32)
SESSION_SECRET=$(openssl rand -hex 32)
DB_PATH=$DIR/data/app.db
TLS=1
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=2026h2026m@gmail.com
SMTP_PASS=
ADMIN_EMAIL=2026h2026m@gmail.com
WD_SLA_HOURS=24
MIN_DEPOSIT_USDT=10
EOF
chmod 600 $DIR/.env

cat > $DIR/schema.sql <<'EOF'
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,pass TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'player',balance REAL NOT NULL DEFAULT 0,currency TEXT NOT NULL DEFAULT 'EUR',
 status TEXT NOT NULL DEFAULT 'active',kyc TEXT NOT NULL DEFAULT 'none',kyc_doc TEXT,
 totp TEXT,verified INTEGER NOT NULL DEFAULT 0,vcode TEXT,referral TEXT,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,uid TEXT NOT NULL,role TEXT NOT NULL,csrf TEXT NOT NULL,exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assets(coin TEXT PRIMARY KEY,network TEXT NOT NULL,address TEXT NOT NULL,on_off INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS deposits(id TEXT PRIMARY KEY,uid TEXT,coin TEXT,network TEXT,amount REAL,txid TEXT,
 status TEXT NOT NULL DEFAULT 'pending',note TEXT,created INTEGER NOT NULL,decided INTEGER);
CREATE TABLE IF NOT EXISTS withdrawals(id TEXT PRIMARY KEY,uid TEXT,coin TEXT,network TEXT,amount REAL,address TEXT,
 status TEXT NOT NULL DEFAULT 'pending',reason TEXT,created INTEGER NOT NULL,decided INTEGER);
CREATE TABLE IF NOT EXISTS wallet_tx(txid TEXT PRIMARY KEY,uid TEXT,amount REAL,kind TEXT,created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS games(id TEXT PRIMARY KEY,title TEXT,provider TEXT,thumb TEXT,rtp REAL,category TEXT);
CREATE TABLE IF NOT EXISTS snapshots(meta TEXT PRIMARY KEY,taken INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS visits(day TEXT PRIMARY KEY,n INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,level TEXT,msg TEXT,created INTEGER NOT NULL,seen INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS kyc_queue(id INTEGER PRIMARY KEY AUTOINCREMENT,uid TEXT,doc TEXT,status TEXT DEFAULT 'pending',created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_dep ON deposits(status,created);
CREATE INDEX IF NOT EXISTS ix_wd ON withdrawals(status,created);
EOF

cat > $DIR/lib.js <<'EOF'
'use strict';
const crypto=require('node:crypto'), fs=require('node:fs');
function env(f){ const o={}; for(const l of fs.readFileSync(f,'utf8').split('\n')){
  if(!l||l.startsWith('#'))continue; const i=l.indexOf('='); if(i<0)continue;
  o[l.slice(0,i).trim()]=l.slice(i+1).trim(); } return o; }
const E=env(process.env.ENV_FILE||'.env');
const K=crypto.scryptSync(E.APP_SECRET,'topcazino.v1',32);
function enc(s){ if(!s)return ''; const iv=crypto.randomBytes(12);
  const c=crypto.createCipheriv('aes-256-gcm',K,iv); const b=Buffer.concat([c.update(s,'utf8'),c.final()]);
  return [iv.toString('base64'),c.getAuthTag().toString('base64'),b.toString('base64')].join('.'); }
function dec(s){ if(!s)return ''; try{ const [i,t,b]=s.split('.');
  const d=crypto.createDecipheriv('aes-256-gcm',K,Buffer.from(i,'base64'));
  d.setAuthTag(Buffer.from(t,'base64'));
  return Buffer.concat([d.update(Buffer.from(b,'base64')),d.final()]).toString('utf8'); }catch{ return ''; } }
const hash=p=>crypto.scryptSync(p,crypto.randomBytes(16),64).toString('hex');
function mk(p){ const s=crypto.randomBytes(16); const h=crypto.scryptSync(p,s,64);
  return s.toString('hex')+':'+h.toString('hex'); }
function chk(p,st){ try{ const [s,h]=st.split(':'); const a=crypto.scryptSync(p,Buffer.from(s,'hex'),64);
  return crypto.timingSafeEqual(a,Buffer.from(h,'hex')); }catch{ return false; } }
function b32(n=20){ const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; const b=crypto.randomBytes(n); let o='';
  for(const x of b) o+=A[x%32]; return o; }
function totp(secret,step=30){
  const A='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits='';
  for(const c of secret) bits+=A.indexOf(c).toString(2).padStart(5,'0');
  const key=Buffer.alloc(bits.length/8); for(let i=0;i<key.length;i++) key[i]=parseInt(bits.substr(i*8,8),2);
  const c=Math.floor(Date.now()/1000/step); const buf=Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(c/2**32),0); buf.writeUInt32BE(c>>>0,4);
  const h=crypto.createHmac('sha1',key).update(buf).digest();
  const o=h[h.length-1]&15;
  return String((h.readUInt32BE(o)&0x7fffffff)%1000000).padStart(6,'0');
}
function totpOk(secret,token){
  if(!secret||!token)return false; const t=token.replace(/\s/g,'');
  for(const d of [-1,0,1]) if(totp(secret)===t) return true;
  return totp(secret)===t;
}
function hmac(body,secret){ return crypto.createHmac('sha256',secret).update(body).digest('hex'); }
module.exports={E,enc,dec,mk,chk,b32,totp,totpOk,hmac};
EOF

cat > $DIR/locales/ar.json <<'EOF'
{"home":"الرئيسية","games":"الألعاب","deposit":"إيداع","account":"حسابي","login":"دخول","register":"تسجيل",
"logout":"خروج","email":"البريد الإلكتروني","password":"كلمة المرور","submit":"متابعة","balance":"الرصيد",
"withdraw":"سحب","amount":"المبلغ","address":"العنوان","copy":"نسخ","copied":"تم النسخ","vip":"VIP","support":"الدعم",
"terms":"الشروط","privacy":"الخصوصية","kyc":"التحقق","responsible":"اللعب المسؤول","footer":"العملات الرقمية فقط · 18+"}
EOF
for L in en fr es de tr ru hi id zh; do cp $DIR/locales/ar.json $DIR/locales/$L.json; done

log "كتابة الواجهة"
cat > $DIR/public/app.css <<'EOF'
:root{--obs:#07070b;--obs2:#0d0d14;--obs3:#14141d;--gold:#d9b45c;--gold2:#f5e3ad;--gold3:#8d6c2a;
--ink:#ece7dc;--dim:#8b8577;--line:rgba(217,180,92,.16);--ok:#3ecf8e;--bad:#e5484d}
*{box-sizing:border-box}
body{margin:0;font-family:Tajawal,system-ui,sans-serif;color:var(--ink);
background:radial-gradient(880px 400px at 50% -10%,rgba(217,180,92,.13),transparent 62%),var(--obs)}
a{color:inherit;text-decoration:none}
.wrap{max-width:1080px;margin:0 auto;padding:0 16px}
header{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--line);
background:rgba(7,7,11,.8);position:sticky;top:0;z-index:50}
.crest{width:38px;height:46px}
.brand b{font-family:Cormorant Garamond,serif;font-size:18px;letter-spacing:2.4px;
background:linear-gradient(100deg,#fdf6e0,#e8c877 40%,#8d6c2a);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand s{display:block;font-size:8px;letter-spacing:3px;color:var(--dim);text-decoration:none}
.sp{flex:1}
.btn{font:inherit;font-size:12px;font-weight:700;padding:9px 14px;border-radius:8px;cursor:pointer;
border:1px solid var(--line);background:transparent;color:var(--ink)}
.btn:hover{border-color:var(--gold);color:var(--gold2)}
.btn.gold{background:linear-gradient(135deg,var(--gold2),var(--gold) 55%,var(--gold3));color:#1a1405;border:0}
.hero{padding:44px 0 26px;text-align:center}
.hero h1{font-size:34px;margin:0 0 12px;line-height:1.25}
.hero h1 em{font-style:normal;background:linear-gradient(100deg,var(--gold2),var(--gold));
-webkit-background-clip:text;background-clip:text;color:transparent}
.hero p{color:var(--dim);max-width:480px;margin:0 auto 20px;line-height:1.9;font-size:14px}
.card{background:var(--obs2);border:1px solid var(--line);border-radius:12px;padding:14px}
.grid{display:grid;gap:10px}
.g3{grid-template-columns:repeat(3,1fr)}.g4{grid-template-columns:repeat(4,1fr)}
@media(max-width:640px){.g3,.g4{grid-template-columns:repeat(2,1fr)}}
.g{position:relative;border-radius:11px;overflow:hidden;border:1px solid var(--line);aspect-ratio:4/5;background:var(--obs3)}
.g img{width:100%;height:100%;object-fit:cover}
.g .sh{position:absolute;inset:0;background:linear-gradient(to top,rgba(5,5,8,.95),transparent 55%)}
.g b{position:absolute;inset:auto 8px 8px;font-size:11px}
h2{font-size:16px;margin:26px 0 12px}
code{display:block;font-size:10px;word-break:break-all;background:#00000066;border:1px solid var(--line);
border-radius:6px;padding:7px;color:var(--gold2);font-family:ui-monospace,monospace}
input,select{width:100%;font:inherit;font-size:13px;padding:10px;border-radius:8px;background:var(--obs3);
border:1px solid var(--line);color:var(--ink);outline:0}
input:focus{border-color:var(--gold)}
label{display:block;font-size:11px;color:var(--dim);margin:0 0 5px}
.fld{margin-bottom:11px}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:8px;border-bottom:1px solid var(--line);text-align:start}
th{color:var(--dim);font-size:10px;letter-spacing:1px}
.badge{font-size:10px;padding:2px 7px;border-radius:5px;border:1px solid}
.p-pending{color:#f5c04a;border-color:#f5c04a55}.p-approved{color:var(--ok);border-color:var(--ok)55}
.p-rejected{color:var(--bad);border-color:var(--bad)55}
footer{margin-top:36px;border-top:1px solid var(--line);padding:18px;font-size:11px;color:var(--dim);text-align:center}
#toast{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);display:none;
background:#14141d;border:1px solid var(--line);border-inline-start:3px solid var(--ok);border-radius:8px;padding:10px 16px;font-size:12px;z-index:99}
EOF

cat > $DIR/public/crest.svg <<'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 44 52"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fdf6e0"/><stop offset=".45" stop-color="#e8c877"/><stop offset="1" stop-color="#8d6c2a"/></linearGradient></defs><path d="M22 2.6 40.6 8.4v18.4c0 11-8.8 19.2-18.6 23C12.2 46 3.4 37.8 3.4 26.8V8.4z" fill="rgba(217,180,92,.07)" stroke="url(#g)" stroke-width="1.3"/><path d="M15.6 15.2h12.8v3.1h-4.8v12.2h4.8v3.1H15.6v-3.1h4.8V18.3h-4.8z" fill="url(#g)"/><path d="M13 12.4l2.6-3.4 2.6 2.6L22 7.4l3.8 4.2 2.6-2.6 2.6 3.4z" fill="url(#g)"/></svg>
EOF

cat > $DIR/views/layout.js <<'EOF'
'use strict';
module.exports=(t,body,o={})=>`<!doctype html><html lang="${o.lang||'ar'}" dir="${o.lang&&o.lang!=='ar'?'ltr':'rtl'}"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${t} · TOPCAZINO</title><meta name="description" content="TOPCAZINO — كازينو مرخّص، إيداع بالعملات الرقمية، سحب خلال 24 ساعة.">
<link rel="icon" href="/crest.svg"><link rel="stylesheet" href="/app.css">
<meta name="csrf" content="${o.csrf||''}"></head><body>
<header><img class="crest" src="/crest.svg" alt="TOPCAZINO"><div class="brand"><b>TOPCAZINO</b><s>OBSIDIAN CLUB</s></div>
<span class="sp"></span>${o.user?`<span class="badge p-approved">${o.user.balance.toFixed(2)} ${o.user.currency}</span>
<a class="btn" href="/account">حسابي</a>${o.user.role!=='player'?'<a class="btn" href="/admin">الإدارة</a>':''}
<a class="btn" href="/logout">خروج</a>`:`<a class="btn" href="/login">دخول</a><a class="btn gold" href="/register">تسجيل</a>`}
</header><main class="wrap">${body}</main>
<footer>TOPCAZINO · العملات الرقمية فقط · 18+ · <a href="/terms">الشروط</a> · <a href="/privacy">الخصوصية</a> · <a href="/responsible">اللعب المسؤول</a></footer>
<div id="toast"></div><script src="/app.js"></script></body></html>`;
EOF

cat > $DIR/public/app.js <<'EOF'
const csrf=document.querySelector('meta[name=csrf]')?.content||'';
const T=m=>{const t=document.getElementById('toast');t.textContent=m;t.style.display='block';
clearTimeout(window._tt);window._tt=setTimeout(()=>t.style.display='none',2600)};
async function post(u,d){const r=await fetch(u,{method:'POST',headers:{'content-type':'application/json','x-csrf':csrf},
body:JSON.stringify(d||{})});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'خطأ');return j}
document.addEventListener('click',async e=>{
 const c=e.target.closest('[data-copy]');
 if(c){try{await navigator.clipboard.writeText(c.dataset.copy);T('تم نسخ العنوان')}catch{T('انسخ يدوياً')}}
 const w=e.target.closest('[data-withdraw]');
 if(w){const a=prompt('المبلغ');if(a)try{await post('/api/withdraw',{amount:+a});T('تم إرسال طلب السحب');setTimeout(()=>location.reload(),900)}catch(x){T(x.message)}}
});
const rf=document.getElementById('regForm');
if(rf)rf.onsubmit=async e=>{e.preventDefault();try{
 await post('/api/register',{email:rf.email.value,password:rf.password.value});
 T('تم — تحقق من بريدك');location.href='/verify'}catch(x){T(x.message)}};
const lf=document.getElementById('loginForm');
if(lf)lf.onsubmit=async e=>{e.preventDefault();try{
 await post('/api/login',{email:lf.email.value,password:lf.password.value,totp:lf.totp?.value});
 location.href='/account'}catch(x){T(x.message)}};
const df=document.getElementById('depForm');
if(df)df.onsubmit=async e=>{e.preventDefault();try{
 await post('/api/deposit',{coin:df.coin.value,amount:+df.amount.value,txid:df.txid.value});
 T('تم — بانتظار مراجعة الإدارة');setTimeout(()=>location.reload(),900)}catch(x){T(x.message)}};
EOF

log "كتابة الخادم"
cat > $DIR/server.js <<'EOF'
'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const L=require('./lib.js');
const layout=require('./views/layout.js');

const E=L.E, PORT=+E.PORT||3000, HOST=E.HOST||'127.0.0.1';
const db=new DatabaseSync(E.DB_PATH);
db.exec(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));

const LANGS=['ar','en','fr','es','de','tr','ru','hi','id','zh'];
const T=()=>JSON.parse(fs.readFileSync(path.join(__dirname,'locales/ar.json'),'utf8'));
const COINS={USDT:['TRC20','ERC20','BEP20','TON'],BTC:['BTC'],ETH:['ERC20'],TON:['TON'],
 LTC:['LTC'],DOGE:['DOGE'],TRX:['TRC20'],BNB:['BEP20'],SOL:['SOL']};

const get=(k,d='')=>db.prepare('SELECT v FROM settings WHERE k=?').get(k)?.v ?? d;
const set=(k,v)=>db.prepare('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k,v);
const now=()=>Math.floor(Date.now()/1000);

/* rate limit */
const RL=new Map();
function rl(ip,max=30,win=60){const b=Math.floor(Date.now()/win/1000),k=ip+':'+b;
 const n=(RL.get(k)||0)+1;RL.set(k,n);if(RL.size>5000)RL.clear();return n<=max;}

function cookies(q){const o={};(q||'').split(';').forEach(p=>{const i=p.indexOf('=');
 if(i>0)o[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())});return o;}
const sec=(s)=>s?s.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])):'';

function send(res,code,body,type='text/html; charset=utf-8',extra={}){
 res.writeHead(code,{'content-type':type,'x-content-type-options':'nosniff',
 'referrer-policy':'strict-origin-when-cross-origin','x-frame-options':'DENY',
 'content-security-policy':"default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self' https:; frame-ancestors 'none'",
 ...extra});res.end(body);}
const json=(res,code,o)=>send(res,code,JSON.stringify(o),'application/json');

function session(req,res){
 const c=cookies(req.headers.cookie),sid=c.sid;
 let s=sid?db.prepare('SELECT * FROM sessions WHERE id=? AND exp>?').get(sid,now()):null;
 if(sid&&!s){res.setHeader('set-cookie','sid=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict');}
 let user=null;
 if(s){user=db.prepare('SELECT * FROM users WHERE id=? AND status=?').get(s.uid,'active');}
 if(!s){const id=crypto.randomBytes(24).toString('hex'),csrf=crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?,?)').run(id,'','guest',csrf,now()+86400);
  res.setHeader('set-cookie',`sid=${id}; Path=/; HttpOnly; SameSite=Strict${E.TLS?'':''}`);
  s={id,uid:'',role:'guest',csrf};}
 return {s,user};
}
function bind(res,sid,uid,role){
 const csrf=crypto.randomBytes(24).toString('hex');
 db.prepare('UPDATE sessions SET uid=?,role=?,csrf=?,exp=? WHERE id=?').run(uid,role,csrf,now()+86400*7,sid);
 res.setHeader('set-cookie',`sid=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${86400*7}${E.TLS?'; Secure':''}`);
}
function csrfOk(req,c){const h=req.headers['x-csrf'];return h&&c.s&&h===c.s.csrf;}

function readJson(req){return new Promise((ok,no)=>{let b='';
 req.on('data',d=>{b+=d;if(b.length>2e6)req.destroy()});req.on('end',()=>{try{ok(JSON.parse(b||'{}'))}catch{ok({})}});no(()=>{});});}

function count(table,where='1'){return db.prepare(`SELECT COUNT(*) n FROM ${table} WHERE ${where}`).get().n;}

/* ---------- pages ---------- */
function home(c){
 const assets=db.prepare('SELECT * FROM assets WHERE on_off=1').all();
 const games=db.prepare('SELECT * FROM games LIMIT 24').all();
 const snap=db.prepare('SELECT taken FROM snapshots WHERE meta=?').get('games');
 const stale=!snap||(now()-snap.taken)*1000>2*3600e3;
 const body=`
 ${stale&&c.user?.role!=='player'?`<div class="card" style="border-color:#e5484d;color:#e5484d;margin-top:12px">تنبيه: بيانات المزود قديمة — شغّل sync</div>`:''}
 <section class="hero"><h1>القمّة ليست مكاناً.<br><em>إنها مقعدك.</em></h1>
 <p>إيداع بالعملات الرقمية فقط · سحب خلال ${sec(get('wd_sla','24'))} ساعة · بلا وسطاء</p>
 <a class="btn gold" href="/register">افتح حسابك</a> <a class="btn" href="#dep">طرق الإيداع</a></section>
 <h2 id="dep">إيداع بالعملات الرقمية</h2>
 ${assets.length?`<div class="grid g3">${assets.map(a=>`<div class="card"><b>${sec(a.coin)} · ${sec(a.network)}</b>
 <code>${sec(a.address)}</code><button class="btn" data-copy="${sec(a.address)}" style="width:100%;margin-top:8px">نسخ</button></div>`).join('')}</div>`
 :'<div class="card">لم تُضف عناوين بعد — الإدارة ← الأصول</div>'}
 <h2>الأكثر لعباً</h2>
 <div class="grid g4">${games.length?games.map(g=>`<a class="g" href="/game/${sec(g.id)}">${g.thumb?`<img src="${sec(g.thumb)}" alt="" loading="lazy" onerror="this.remove()">`:''}<div class="sh"></div><b>${sec(g.title)}</b></a>`).join(''):'<div class="card">الكتالوج قيد التحميل</div>'}</div>`;
 return layout('الرئيسية',body,{user:c.user,csrf:c.s.csrf});
}

function authPage(kind,c){const reg=kind==='reg';
 return layout(reg?'تسجيل':'دخول',`<h2>${reg?'تسجيل حساب':'دخول'}</h2>
 <form class="card" id="${reg?'regForm':'loginForm'}" style="max-width:380px">
 <div class="fld"><label>البريد</label><input name="email" type="email" required></div>
 <div class="fld"><label>كلمة المرور</label><input name="password" type="password" required minlength="8"></div>
 ${reg?'<div class="fld"><label>كود الإحالة</label><input name="ref"></div>':'<div class="fld"><label>رمز 2FA (للإدارة)</label><input name="totp" inputmode="numeric"></div>'}
 <button class="btn gold" style="width:100%">${reg?'إنشاء':'دخول'}</button></form>`,{csrf:c.s.csrf});}

function account(c){const u=c.user;
 if(!u)return layout('حسابي',`<h2>سجل الدخول</h2>`);
 const deps=db.prepare('SELECT * FROM deposits WHERE uid=? ORDER BY created DESC LIMIT 20').all(u.id);
 const wds=db.prepare('SELECT * FROM withdrawals WHERE uid=? ORDER BY created DESC LIMIT 20').all(u.id);
 const assets=db.prepare('SELECT * FROM assets WHERE on_off=1').all();
 return layout('حسابي',`<h2>حسابي · ${u.balance.toFixed(2)} ${sec(u.currency)}</h2>
 <div class="grid g3"><div class="card"><b>إيداع جديد</b>
 <form id="depForm" style="margin-top:8px"><div class="fld"><label>العملة</label><select name="coin">
 ${assets.map(a=>`<option value="${sec(a.coin)}">${sec(a.coin)} ${sec(a.network)}</option>`).join('')}</select></div>
 <div class="fld"><label>المبلغ</label><input name="amount" type="number" step="0.01" required></div>
 <div class="fld"><label>هاش التحويل</label><input name="txid" required></div>
 <button class="btn gold" style="width:100%">إرسال</button></form></div>
 <div class="card"><b>سحب</b><p style="font-size:11px;color:var(--dim)">يُنفّذ خلال ${sec(get('wd_sla','24'))} ساعة</p>
 <button class="btn" data-withdraw="1" style="width:100%">طلب سحب</button></div>
 <div class="card"><b>KYC</b><p style="font-size:11px;color:var(--dim)">الحالة: ${sec(u.kyc)}</p>
 <button class="btn" style="width:100%" onclick="document.getElementById('kyc').click()">رفع مستند</button>
 <input id="kyc" type="file" hidden></div></div>
 <h2>الإيداعات</h2><table><tr><th>العملة</th><th>المبلغ</th><th>الحالة</th><th>التاريخ</th></tr>
 ${deps.map(d=>`<tr><td>${sec(d.coin)}</td><td>${d.amount}</td><td><span class="badge p-${sec(d.status)}">${sec(d.status)}</span></td><td>${new Date(d.created*1000).toLocaleString('ar')}</td></tr>`).join('')||'<tr><td colspan="4">—</td></tr>'}</table>
 <h2>السحوبات</h2><table><tr><th>العملة</th><th>المبلغ</th><th>الحالة</th><th>السبب</th></tr>
 ${wds.map(d=>`<tr><td>${sec(d.coin)}</td><td>${d.amount}</td><td><span class="badge p-${sec(d.status)}">${sec(d.status)}</span></td><td>${sec(d.reason||'')}</td></tr>`).join('')||'<tr><td colspan="4">—</td></tr>'}</table>`,
 {user:u,csrf:c.s.csrf});}

function adminPage(c){const u=c.user;
 if(!u||u.role==='player')return layout('الإدارة',`<h2>دخول الإدارة</h2>
 <form class="card" id="loginForm" style="max-width:360px"><div class="fld"><label>البريد</label><input name="email"></div>
 <div class="fld"><label>كلمة المرور</label><input name="password" type="password"></div>
 <div class="fld"><label>2FA</label><input name="totp"></div><button class="btn gold">دخول</button></form>`,{csrf:c.s.csrf});
 const deps=db.prepare('SELECT d.*,u.email FROM deposits d JOIN users u ON u.id=d.uid WHERE d.status=? ORDER BY d.created DESC LIMIT 50').all('pending');
 const wds=db.prepare('SELECT w.*,u.email FROM withdrawals w JOIN users u ON u.id=w.uid WHERE w.status=? ORDER BY w.created DESC LIMIT 50').all('pending');
 const al=db.prepare('SELECT * FROM alerts WHERE seen=0 ORDER BY id DESC LIMIT 20').all();
 const day=new Date().toISOString().slice(0,10);
 const v=db.prepare('SELECT n FROM visits WHERE day=?').get(day)?.n||0;
 const sla=now()-(+get('wd_sla','24'))*3600;
 const late=count('withdrawals',`status='pending' AND created<${sla}`);
 return layout('الإدارة',`<h2>لوحة الإدارة</h2>
 <div class="grid g4">
 <div class="card"><b>${v}</b><div style="font-size:10px;color:var(--dim)">زوار اليوم</div></div>
 <div class="card"><b>${count('users')}</b><div style="font-size:10px;color:var(--dim)">مشتركون</div></div>
 <div class="card"><b>${deps.length}</b><div style="font-size:10px;color:var(--dim)">إيداعات معلّقة</div></div>
 <div class="card" ${late?'style="border-color:#e5484d"':''}><b>${late}</b><div style="font-size:10px;color:var(--dim)">سحوبات متأخرة</div></div></div>
 ${al.length?`<div class="card" style="border-color:#e5484d;margin-top:10px">${al.map(a=>`<div style="font-size:11px">${sec(a.msg)}</div>`).join('')}</div>`:''}
 <h2>الإيداعات المعلّقة</h2><table><tr><th>اللاعب</th><th>العملة</th><th>المبلغ</th><th>txid</th><th></th></tr>
 ${deps.map(d=>`<tr><td>${sec(d.email)}</td><td>${sec(d.coin)}</td><td>${d.amount}</td><td style="font-size:10px">${sec(d.txid)}</td>
 <td><button class="btn" onclick="dec('deposit','${d.id}','approved')">قبول</button>
 <button class="btn" onclick="dec('deposit','${d.id}','rejected')">رفض</button></td></tr>`).join('')||'<tr><td colspan="5">—</td></tr>'}</table>
 <h2>السحوبات المعلّقة</h2><table><tr><th>اللاعب</th><th>العملة</th><th>المبلغ</th><th>العنوان</th><th></th></tr>
 ${wds.map(d=>`<tr><td>${sec(d.email)}</td><td>${sec(d.coin)}</td><td>${d.amount}</td><td style="font-size:10px">${sec(d.address)}</td>
 <td><button class="btn" onclick="dec('withdrawal','${d.id}','approved')">قبول</button>
 <button class="btn" onclick="dec('withdrawal','${d.id}','rejected')">رفض</button></td></tr>`).join('')||'<tr><td colspan="5">—</td></tr>'}</table>
 <h2>الأصول</h2><form class="card" onsubmit="addAsset(event)"><div class="grid g3">
 <div class="fld"><label>العملة</label><input id="ac" placeholder="USDT"></div>
 <div class="fld"><label>الشبكة</label><input id="an" placeholder="TRC20"></div>
 <div class="fld"><label>العنوان</label><input id="aa"></div></div>
 <button class="btn gold">إضافة</button>
 <a class="btn" href="/admin/export.csv">تصدير CSV</a></form>
 <script>const C=document.querySelector('meta[name=csrf]').content;
 async function dec(k,id,s){const r=prompt('السبب')||'';await fetch('/admin/'+k+'/'+id,{method:'POST',
 headers:{'content-type':'application/json','x-csrf':C},body:JSON.stringify({status:s,reason:r})});location.reload()}
 async function addAsset(e){e.preventDefault();await fetch('/admin/asset',{method:'POST',
 headers:{'content-type':'application/json','x-csrf':C},body:JSON.stringify({coin:ac.value,network:an.value,address:aa.value})});location.reload()}</script>`,
 {user:u,csrf:c.s.csrf});}

/* ---------- api ---------- */
async function api(req,res,url,c){
 const p=url.pathname;
 if(!csrfOk(req,c))return json(res,403,{error:'CSRF'});
 if(p==='/api/register'){
  const b=await readJson(req);
  if(!/^\S+@\S+\.\S+$/.test(b.email||''))return json(res,400,{error:'بريد غير صالح'});
  if((b.password||'').length<8)return json(res,400,{error:'كلمة المرور قصيرة'});
  if(db.prepare('SELECT 1 FROM users WHERE email=?').get(b.email))return json(res,409,{error:'البريد مستخدم'});
  const id=crypto.randomBytes(12).toString('hex'),code=String(crypto.randomInt(100000,999999));
  db.prepare(`INSERT INTO users(id,email,pass,role,currency,vcode,referral,created)
   VALUES(?,?,?,?,?,?,?,?)`).run(id,b.email,L.mk(b.password),'player',get('currency','EUR'),code,b.ref||'',now());
  bind(res,c.s.id,id,'player');
  if(get('smtp_pass'))await mail(b.email,'رمز التحقق',`رمزك: ${code}`);
  return json(res,200,{ok:1});}
 if(p==='/api/login'){
  const b=await readJson(req);
  const u=db.prepare('SELECT * FROM users WHERE email=?').get(b.email||'');
  if(!u||!L.chk(b.password||'',u.pass))return json(res,401,{error:'بيانات خاطئة'});
  if(u.role!=='player'&&u.totp&&!L.totpOk(u.totp,b.totp))return json(res,401,{error:'رمز 2FA مطلوب'});
  bind(res,c.s.id,u.id,u.role);return json(res,200,{ok:1});}
 if(!c.user)return json(res,401,{error:'سجّل الدخول'});
 const u=c.user;
 if(p==='/api/deposit'){
  const b=await readJson(req);
  const net=COINS[b.coin]; if(!net)return json(res,400,{error:'عملة غير مدعومة'});
  if(!(+b.amount>0))return json(res,400,{error:'مبلغ غير صالح'});
  const id=crypto.randomBytes(10).toString('hex');
  db.prepare('INSERT INTO deposits(id,uid,coin,network,amount,txid,created) VALUES(?,?,?,?,?,?,?)')
   .run(id,u.id,b.coin,net[0],+b.amount,b.txid||'',now());
  return json(res,200,{ok:1});}
 if(p==='/api/withdraw'){
  const b=await readJson(req),amt=+b.amount;
  if(!(amt>0))return json(res,400,{error:'مبلغ غير صالح'});
  if(amt>u.balance)return json(res,400,{error:'رصيد غير كافٍ'});
  const id=crypto.randomBytes(10).toString('hex');
  db.exec('BEGIN');try{
   db.prepare('UPDATE users SET balance=balance-? WHERE id=? AND balance>=?').run(amt,u.id,amt);
   db.prepare('INSERT INTO withdrawals(id,uid,coin,network,amount,address,created) VALUES(?,?,?,?,?,?,?)')
    .run(id,u.id,'USDT','TRC20',amt,b.address||'',now());
   db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');return json(res,500,{error:'فشل'})}
  return json(res,200,{ok:1});}
 return json(res,404,{error:'؟'});
}

async function adminApi(req,res,url,c){
 if(!c.user||c.user.role==='player')return json(res,403,{error:'صلاحية'});
 if(!csrfOk(req,c))return json(res,403,{error:'CSRF'});
 const m=url.pathname.match(/^\/admin\/(deposit|withdrawal)\/([a-f0-9]+)$/);
 if(m&&req.method==='POST'){
  const b=await readJson(req),t=m[1]==='deposit'?'deposits':'withdrawals';
  const row=db.prepare(`SELECT * FROM ${t} WHERE id=?`).get(m[2]);
  if(!row||row.status!=='pending')return json(res,400,{error:'منتهي'});
  db.exec('BEGIN');try{
   if(t==='deposits'&&b.status==='approved')
     db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(row.amount,row.uid);
   if(t==='withdrawals'&&b.status==='rejected')
     db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(row.amount,row.uid);
   db.prepare(`UPDATE ${t} SET status=?,note=?,decided=? WHERE id=?`).run(b.status,b.reason||'',now(),row.id);
   db.exec('COMMIT');}catch(e){db.exec('ROLLBACK');return json(res,500,{error:'فشل'})}
  return json(res,200,{ok:1});}
 if(url.pathname==='/admin/asset'){
  const b=await readJson(req);
  if(!COINS[b.coin]||!COINS[b.coin].includes(b.network))return json(res,400,{error:'زوج غير مدعوم'});
  db.prepare('INSERT INTO assets(coin,network,address) VALUES(?,?,?) ON CONFLICT(coin) DO UPDATE SET network=excluded.network,address=excluded.address')
   .run(b.coin,b.network,b.address);
  return json(res,200,{ok:1});}
 return json(res,404,{error:'؟'});
}

async function mail(to,sub,text){
 try{
  const nodemailer=null; // SMTP عبر node خالص
  const net=require('node:net');
  const u=E.SMTP_USER,p=E.SMTP_PASS; if(!p)return;
  const s=net.connect(587,E.SMTP_HOST||'smtp.gmail.com');
  const w=l=>s.write(l+'\r\n');
  const msg=[`From: TOPCAZINO <${u}>`,`To: ${to}`,`Subject: ${sub}`,'MIME-Version: 1.0',
   'Content-Type: text/plain; charset=utf-8','',text].join('\r\n');
  let step=0;
  s.on('data',d=>{const r=d.toString();
   if(step===0&&r.startsWith('220')){step=1;w('EHLO topcazino')}
   else if(step===1&&/250 .*/.test(r)){step=2;w('AUTH LOGIN')}
   else if(step===2&&r.startsWith('334')){step=3;w(Buffer.from(u).toString('base64'))}
   else if(step===3&&r.startsWith('334')){step=4;w(Buffer.from(p).toString('base64'))}
   else if(step===4&&r.startsWith('235')){step=5;w(`MAIL FROM:<${u}>`)}
   else if(step===5&&r.startsWith('250')){step=6;w(`RCPT TO:<${to}>`)}
   else if(step===6&&r.startsWith('250')){step=7;w('DATA')}
   else if(step===7&&r.startsWith('354')){step=8;s.write(msg+'\r\n.\r\n')}
   else if(step===8&&r.startsWith('250')){s.end('QUIT')}});
  s.on('error',()=>{});
 }catch{}
}

/* ---------- static ---------- */
const MIME={'.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
function staticFile(req,res,url){
 const f=path.join(__dirname,'public',path.normalize(url.pathname).replace(/^(\.\.[/\\])+/, ''));
 if(!f.startsWith(path.join(__dirname,'public')))return false;
 if(!fs.existsSync(f)||!fs.statSync(f).isFile())return false;
 send(res,200,fs.readFileSync(f),MIME[path.extname(f)]||'application/octet-stream',
  {'cache-control':'public,max-age=3600'});return true;}

/* ---------- server ---------- */
const srv=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://x');
 const ip=(req.headers['x-forwarded-for']||'').split(',')[0].trim()||req.socket.remoteAddress||'0';
 if(!rl(ip,120,60))return send(res,429,'كثير من الطلبات');
 const c=session(req,res);
 if(req.method==='GET'&&!url.pathname.startsWith('/api')&&url.pathname!=='/healthz'){
  db.prepare('INSERT INTO visits(day,n) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET n=n+1').run(new Date().toISOString().slice(0,10));}
 try{
  if(url.pathname==='/healthz')return json(res,200,{ok:1,t:now()});
  if(req.method==='GET'&&staticFile(req,res,url))return;
  if(url.pathname.startsWith('/api/'))return await api(req,res,url,c);
  if(url.pathname.startsWith('/admin'))return await adminApi(req,res,url,c);
  if(url.pathname==='/logout'){db.prepare('DELETE FROM sessions WHERE id=?').run(c.s.id);
   return send(res,302,'','text/plain',{'location':'/'});}
  if(req.method==='GET'){
   switch(url.pathname){
    case '/':return send(res,200,home(c));
    case '/login':return send(res,200,authPage('login',c));
    case '/register':return send(res,200,authPage('reg',c));
    case '/account':return send(res,200,account(c));
    case '/admin':return send(res,200,adminPage(c));
    case '/terms':case '/privacy':case '/responsible':
     return send(res,200,layout('معلومات',`<h2>${sec(url.pathname.slice(1))}</h2>
      <div class="card">صفحة ${sec(url.pathname)} — تُحرَّر من الإدارة. العملات الرقمية فقط · 18+ · سحب خلال ${sec(get('wd_sla','24'))} ساعة.</div>`));
    case '/admin/export.csv':{
     if(!c.user||c.user.role==='player')return send(res,403,'');
     const rows=db.prepare('SELECT * FROM deposits').all();
     const csv='id,uid,coin,amount,status\n'+rows.map(r=>[r.id,r.uid,r.coin,r.amount,r.status].join(',')).join('\n');
     return send(res,200,csv,'text/csv',{'content-disposition':'attachment;filename=deposits.csv'});}
   }
   const gm=url.pathname.match(/^\/game\/([a-z0-9_-]+)$/i);
   if(gm){const g=db.prepare('SELECT * FROM games WHERE id=?').get(gm[1]);
    return send(res,200,layout(sec(g?.title||'لعبة'),`<h2>${sec(g?.title||'')}</h2>
     <div class="card">${g?.thumb?`<img src="${sec(g.thumb)}" style="max-width:240px;border-radius:10px">`:''}
     <p>RTP: ${g?.rtp||'—'}% · ${sec(g?.provider||'')}</p>
     <a class="btn gold" href="/account">العب</a></div>`));}
  }
  send(res,404,layout('404','<h2>غير موجود</h2>'));
 }catch(e){console.error(e);send(res,500,'خطأ داخلي');}
});

/* seed admin */
(function(){
 const em=get('admin_email');
 if(!em){set('admin_email',E.ADMIN_EMAIL||'admin@localhost');
  const pw=crypto.randomBytes(6).toString('base64url'),tp=L.b32(16);
  db.prepare(`INSERT INTO users(id,email,pass,role,totp,verified,created) VALUES(?,?,?,?,?,1,?)`)
   .run(crypto.randomBytes(8).toString('hex'),E.ADMIN_EMAIL||'admin@localhost',L.mk(pw),'owner',tp,now());
  fs.writeFileSync(path.join(__dirname,'logs/admin-seed.txt'),
   `ADMIN: ${E.ADMIN_EMAIL}\nPASSWORD: ${pw}\n2FA SECRET: ${tp}\n`);
  console.log('admin seed →',pw,tp);}
 set('wd_sla',get('wd_sla',E.WD_SLA_HOURS||'24'));
})();

srv.listen(PORT,HOST,()=>console.log('TOPCAZINO on',HOST+':'+PORT));
process.on('SIGTERM',()=>{srv.close();db.close();process.exit(0)});
EOF

cat > $DIR/deploy/topcazino.service <<EOF
[Unit]
Description=TOPCAZINO
After=network.target

[Service]
Type=simple
User=$APP
WorkingDirectory=$DIR
EnvironmentFile=$DIR/.env
ExecStart=/usr/bin/node --experimental-sqlite server.js
Restart=always
RestartSec=3
NoNewPrivileges=1
PrivateTmp=1
ProtectSystem=strict
ProtectHome=1
ReadWritePaths=$DIR/data $DIR/logs
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/nginx/sites-available/$APP <<EOF
server {
  listen 80; server_name $DOMAIN;
  client_max_body_size 12m;
  add_header X-Content-Type-Options nosniff;
  location / { proxy_pass http://127.0.0.1:3000; proxy_http_version 1.1;
    proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme; }
}
EOF
ln -sf /etc/nginx/sites-available/$APP /etc/nginx/sites-enabled/$APP
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

chown -R $APP:$APP $DIR
chmod 600 $DIR/.env

log "تشغيل الخدمة"
systemctl daemon-reload
systemctl enable --now $APP
sleep 2
curl -fsS http://127.0.0.1:3000/healthz || die "الخدمة لم تعمل — journalctl -u $APP"

log "الجدار الناري"
ufw allow 22/tcp >/dev/null; ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
yes | ufw enable >/dev/null || true

if [ -n "$EMAIL" ]; then
  log "شهادة TLS"
  certbot --nginx -d "$DOMAIN" -m "$EMAIL" --agree-tos --non-interactive --redirect || \
    echo "⚠ فشل certbot — أعد المحاولة يدوياً بعد ضبط DNS"
fi

log "نسخ احتياطي يومي"
cat > $DIR/scripts/backup.sh <<EOF
#!/bin/sh
sqlite3 $DIR/data/app.db ".backup '$DIR/data/b-\$(date +%F).db'"
find $DIR/data -name 'b-*.db' -mtime +14 -delete
EOF
chmod +x $DIR/scripts/backup.sh
echo "17 3 * * * $APP $DIR/scripts/backup.sh" > /etc/cron.d/$APP

echo
printf '\033[1;32m✓ تم النشر\033[0m\n\n'
echo "الموقع:    https://$DOMAIN"
echo "الإدارة:   https://$DOMAIN/admin"
echo "بيانات المدير الأول:"
cat $DIR/logs/admin-seed.txt
echo
echo "التالي:"
echo " 1. أضف SMTP_PASS (App Password من Gmail) في $DIR/.env ثم: systemctl restart $APP"
echo " 2. أضف عنوان محفظتك من الإدارة ← الأصول"
echo " 3. أضف مفتاح المزود: node $DIR/scripts/keyget.js && node $DIR/scripts/sync.js"
echo " 4. غيّر كلمة مرور المدير من /account"
echo
echo "السجلات: journalctl -u $APP -f"
