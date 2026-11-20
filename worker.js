const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400"
};
const CATALOG = {
  "Big Mac": 55,
  "McNuggets 6 Stück": 45,
  "Pommes groß": 35,
  "Cola": 20
};

function json(data, status=200) {
  return new Response(JSON.stringify(data), { status, headers: { ...CORS_HEADERS, "Content-Type":"application/json; charset=utf-8" } });
}
async function sha256(text) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map(b=>b.toString(16).padStart(2,"0")).join("");
}
function base64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
async function makePasswordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations:150000,hash:"SHA-256"},key,256);
  return base64(bits);
}
async function createSession(env, userId, role) {
  const token = randomToken();
  const tokenHash = await sha256(token);
  await env.DB.prepare("INSERT INTO sessions (token_hash,user_id,role,expires_at) VALUES (?,?,?,datetime('now','+7 days'))")
    .bind(tokenHash,userId,role).run();
  return token;
}
async function auth(request, env) {
  const header=request.headers.get("Authorization")||"";
  const token=header.startsWith("Bearer ")?header.slice(7):"";
  if(!token)return null;
  const tokenHash=await sha256(token);
  const row=await env.DB.prepare("SELECT s.user_id,s.role,u.name,u.coins FROM sessions s LEFT JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>datetime('now')").bind(tokenHash).first();
  return row || null;
}
async function body(request) { try { return await request.json(); } catch { return {}; } }
function cleanName(value) { return typeof value==="string"?value.trim().replace(/\s+/g," "):""; }
function cleanText(value,max=1000) { return typeof value==="string"?value.trim().slice(0,max):""; }
async function requireRole(request,env,role) {
  const session=await auth(request,env);
  if(!session || session.role!==role) return null;
  return session;
}

export default {
  async fetch(request, env) {
    if(request.method==="OPTIONS")return new Response(null,{status:204,headers:CORS_HEADERS});
    const url=new URL(request.url); const path=url.pathname;
    try {
      if(path==="/api/health" && request.method==="GET")return json({ok:true,service:"Ducky Support API"});

      if(path==="/api/register" && request.method==="POST") {
        const data=await body(request); const name=cleanName(data.name); const password=typeof data.password==="string"?data.password:"";
        if(name.length<3||name.length>24||!/^[\p{L}\p{N}_ -]+$/u.test(name))return json({error:"Name muss 3–24 Zeichen haben (Buchstaben, Zahlen, _ oder -)."},400);
        if(password.length<8||password.length>128)return json({error:"Passwort muss mindestens 8 Zeichen haben."},400);
        const salt=randomToken(); const passwordHash=await makePasswordHash(password,salt);
        try { const result=await env.DB.prepare("INSERT INTO users (name,password_hash,password_salt) VALUES (?,?,?)").bind(name,passwordHash,salt).run();
          const userId=result.meta.last_row_id; const token=await createSession(env,userId,"user");
          return json({token,user:{name,coins:500,role:"user"}},201);
        } catch { return json({error:"Dieser Spielername ist bereits vergeben."},409); }
      }

      if(path==="/api/login" && request.method==="POST") {
        const data=await body(request); const name=cleanName(data.name); const password=typeof data.password==="string"?data.password:"";
        const user=await env.DB.prepare("SELECT id,name,password_hash,password_salt,coins FROM users WHERE name=? COLLATE NOCASE").bind(name).first();
        if(!user || await makePasswordHash(password,user.password_salt)!==user.password_hash)return json({error:"Name oder Passwort falsch."},401);
        const token=await createSession(env,user.id,"user"); return json({token,user:{name:user.name,coins:user.coins,role:"user"}});
      }

      if(path==="/api/admin/login" && request.method==="POST") {
        const data=await body(request); if(!env.ADMIN_PASSWORD)return json({error:"Admin-Passwort ist am Cloudflare-Worker noch nicht eingerichtet."},503);
        if(typeof data.password!=="string" || data.password!==env.ADMIN_PASSWORD)return json({error:"Falscher Admin-Code."},401);
        const token=await createSession(env,null,"admin"); return json({token,user:{name:"ADMIN",role:"admin"}});
      }

      if(path==="/api/me" && request.method==="GET") {
        const session=await auth(request,env); if(!session)return json({error:"Bitte erneut anmelden."},401);
        return json({user:{name:session.name||"ADMIN",coins:session.coins??null,role:session.role}});
      }

      if(path==="/api/logout" && request.method==="POST") {
        const header=request.headers.get("Authorization")||""; const token=header.startsWith("Bearer ")?header.slice(7):"";
        if(token)await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await sha256(token)).run();
        return json({ok:true});
      }

      if(path==="/api/messages" && request.method==="POST") {
        const session=await requireRole(request,env,"user"); if(!session)return json({error:"Bitte anmelden."},401);
        const data=await body(request); const text=cleanText(data.text);
        if(!text)return json({error:"Nachricht darf nicht leer sein."},400);
        const result=await env.DB.prepare("INSERT INTO messages (user_id,sender_role,text) VALUES (?, 'user', ?)").bind(session.user_id,text).run();
        return json({message:{id:result.meta.last_row_id,user_id:session.user_id,sender_role:"user",sender_name:session.name,text,created_at:new Date().toISOString()}},201);
      }

      if(path==="/api/messages" && request.method==="GET") {
        const session=await requireRole(request,env,"user"); if(!session)return json({error:"Bitte anmelden."},401);
        const result=await env.DB.prepare("SELECT id,sender_role,text,created_at FROM (SELECT id,sender_role,text,created_at FROM messages WHERE user_id=? ORDER BY id DESC LIMIT 200) ORDER BY id ASC").bind(session.user_id).all();
        return json({messages:result.results,user:{coins:session.coins}});
      }

      if(path==="/api/admin/messages" && request.method==="GET") {
        const session=await requireRole(request,env,"admin"); if(!session)return json({error:"Admin-Anmeldung erforderlich."},401);
        const result=await env.DB.prepare("SELECT m.id,m.user_id,m.sender_role,m.text,m.created_at,u.name AS user_name FROM messages m JOIN users u ON u.id=m.user_id ORDER BY m.id DESC LIMIT 300").all();
        return json({messages:result.results});
      }

      if(path==="/api/admin/reply" && request.method==="POST") {
        const session=await requireRole(request,env,"admin"); if(!session)return json({error:"Admin-Anmeldung erforderlich."},401);
        const data=await body(request); const userName=cleanName(data.userName); const text=cleanText(data.text);
        if(!userName||!text)return json({error:"Spielername und Nachricht sind erforderlich."},400);
        const user=await env.DB.prepare("SELECT id FROM users WHERE name=? COLLATE NOCASE").bind(userName).first();
        if(!user)return json({error:"Spieler wurde nicht gefunden."},404);
        await env.DB.prepare("INSERT INTO messages (user_id,sender_role,text) VALUES (?, 'admin', ?)").bind(user.id,text).run();
        return json({ok:true});
      }

      if(path==="/api/admin/users" && request.method==="GET") {
        const session=await requireRole(request,env,"admin"); if(!session)return json({error:"Admin-Anmeldung erforderlich."},401);
        const result=await env.DB.prepare("SELECT name,coins,created_at FROM users ORDER BY created_at DESC LIMIT 500").all();
        return json({users:result.results});
      }

      if(path==="/api/order" && request.method==="POST") {
        const session=await requireRole(request,env,"user"); if(!session)return json({error:"Bitte anmelden."},401);
        const data=await body(request); if(!Array.isArray(data.items)||!data.items.length||data.items.length>30)return json({error:"Warenkorb ist ungültig."},400);
        let total=0; const safeItems=[];
        for(const item of data.items){const name=cleanText(item?.name,60);if(!(name in CATALOG))return json({error:"Unbekannter Artikel: "+name},400);total+=CATALOG[name];safeItems.push({name,price:CATALOG[name]});}
        const update=await env.DB.prepare("UPDATE users SET coins=coins-? WHERE id=? AND coins>=?").bind(total,session.user_id,total).run();
        if(update.meta.changes!==1)return json({error:"Du hast nicht genügend Coins."},400);
        await env.DB.prepare("INSERT INTO orders (user_id,items_json,total) VALUES (?,?,?)").bind(session.user_id,JSON.stringify(safeItems),total).run();
        const user=await env.DB.prepare("SELECT coins FROM users WHERE id=?").bind(session.user_id).first();
        const orderText="McDonald's Bestellung: "+safeItems.map(i=>i.name).join(", ");
        await env.DB.prepare("INSERT INTO messages (user_id,sender_role,text) VALUES (?, 'user', ?)").bind(session.user_id,orderText).run();
        return json({ok:true,charged:total,coins:user.coins});
      }

      return json({error:"API-Endpunkt nicht gefunden."},404);
    } catch(error) {
      return json({error:"Serverfehler. Prüfe Worker und D1-Einrichtung.",detail:env.ENVIRONMENT==="development"?String(error):undefined},500);
    }
  }
};
