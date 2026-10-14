

const BASE = "https://little-elsewhere-tiktok.paul-rodrigue44.workers.dev";

const REDIRECT_URI = BASE + "/callback";

const ACCOUNT_ID = "little-elsewhere";

const SCOPES = "user.info.basic,video.list";



const encoder = new TextEncoder();

const decoder = new TextDecoder();



const HEADERS = {

  "Cache-Control": "no-store",

  "Referrer-Policy": "no-referrer",

  "X-Content-Type-Options": "nosniff",

  "X-Frame-Options": "DENY"

};



function html(content, status = 200, headers = {}) {

  return new Response(

    `<!doctype html>

<html lang="fr">

<head>

<meta charset="utf-8">

<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Little Elsewhere Analytics</title>

<style>

body {

  font-family: system-ui, sans-serif;

  max-width: 800px;

  margin: 60px auto;

  padding: 20px;

  line-height: 1.6;

}

a { color: #347fdb; }


.tab-panel[hidden] { display:none !important; }
#dashboardTabs .tab-button { background:#1b2944;color:#c4d2e8;border:1px solid #344762; }
#dashboardTabs .tab-button.active { background:#327ed1;color:white;border-color:#569ce7; }
#dashboardTabs .tab-button:focus-visible { outline:3px solid #a8d5ff;outline-offset:2px; }
.filters{display:flex;flex-wrap:wrap;gap:12px;margin:18px 0}.filters label{display:flex;flex-direction:column;gap:6px;color:#cbd7ee;font-size:14px}.filters input,.filters select{background:#101b31;border:1px solid #415473;color:#fff;padding:11px;border-radius:9px;min-width:180px;max-width:100%}.insight-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.insight-card{background:#101a30;border:1px solid #2b3a58;padding:16px;border-radius:12px;min-width:0}.insight-card strong{font-size:26px;display:block;margin-top:8px}.insight-card p{font-size:13px;overflow-wrap:anywhere}.trend-accelerating{color:#8de1af}.trend-slowing{color:#ffc68a}.trend-insufficient{color:#9aaac7}@media(max-width:650px){main{padding:18px 12px}h1{font-size:30px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.value{font-size:24px}#dashboardTabs .tab-button{flex:1;padding:12px 8px}.table-wrap{overflow-x:auto}} 
</style>

</head>

<body>${content}</body>

</html>`,

    {

      status,

      headers: {

        "Content-Type": "text/html; charset=utf-8",

        ...HEADERS,

        ...headers

      }

    }

  );

}



function json(data, status = 200, headers = {}) {

  return new Response(JSON.stringify(data), {

    status,

    headers: {

      "Content-Type": "application/json; charset=utf-8",

      ...HEADERS,

      ...headers

    }

  });

}



function randomHex(length = 24) {

  return Array.from(

    crypto.getRandomValues(new Uint8Array(length)),

    b => b.toString(16).padStart(2, "0")

  ).join("");

}



function toBase64(bytes) {

  return btoa(String.fromCharCode(...bytes));

}



function fromBase64(value) {

  return Uint8Array.from(

    atob(value),

    c => c.charCodeAt(0)

  );

}



async function hmac(value, secret) {

  const key = await crypto.subtle.importKey(

    "raw",

    encoder.encode(secret),

    { name: "HMAC", hash: "SHA-256" },

    false,

    ["sign"]

  );



  const result = await crypto.subtle.sign(

    "HMAC",

    key,

    encoder.encode(value)

  );



  return Array.from(

    new Uint8Array(result),

    b => b.toString(16).padStart(2, "0")

  ).join("");

}



function getCookie(request, name) {

  const cookies = request.headers.get("Cookie") || "";

  const item = cookies

    .split(";")

    .map(x => x.trim())

    .find(x => x.startsWith(name + "="));



  return item ? item.slice(name.length + 1) : null;

}



const CLEAR_STATE =

  "tt_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";



async function encryptionKey(env) {

  const raw = fromBase64(env.TIKTOK_ENCRYPTION_KEY);



  if (raw.length !== 32) {

    throw new Error("Invalid encryption key");

  }



  return crypto.subtle.importKey(

    "raw",

    raw,

    { name: "AES-GCM" },

    false,

    ["encrypt", "decrypt"]

  );

}



async function encrypt(value, env) {

  const key = await encryptionKey(env);

  const iv = crypto.getRandomValues(new Uint8Array(12));



  const ciphertext = await crypto.subtle.encrypt(

    { name: "AES-GCM", iv },

    key,

    encoder.encode(value)

  );



  return (

    toBase64(iv) +

    "." +

    toBase64(new Uint8Array(ciphertext))

  );

}



async function decrypt(value, env) {

  const [iv, data] = value.split(".");



  if (!iv || !data) {

    throw new Error("Invalid encrypted value");

  }



  const key = await encryptionKey(env);



  const plaintext = await crypto.subtle.decrypt(

    { name: "AES-GCM", iv: fromBase64(iv) },

    key,

    fromBase64(data)

  );



  return decoder.decode(plaintext);

}



async function tokenRequest(params, env) {

  const response = await fetch(

    "https://open.tiktokapis.com/v2/oauth/token/",

    {

      method: "POST",

      headers: {

        "Content-Type": "application/x-www-form-urlencoded"

      },

      body: new URLSearchParams({

        client_key: env.TIKTOK_CLIENT_KEY,

        client_secret: env.TIKTOK_CLIENT_SECRET,

        ...params

      })

    }

  );



  const result = await response.json();



  if (!response.ok || !result.access_token) {

    throw new Error("TikTok token request failed");

  }



  return result;

}



async function saveTokens(env, token, existing = null) {

  const now = Math.floor(Date.now() / 1000);



  const access = await encrypt(token.access_token, env);



  const refreshValue =

    token.refresh_token || existing?.refresh_token;



  if (!refreshValue) {

    throw new Error("Missing refresh token");

  }



  const refresh = await encrypt(refreshValue, env);



  const accessExpiry = now + Number(token.expires_in);



  const refreshExpiry = token.refresh_expires_in

    ? now + Number(token.refresh_expires_in)

    : existing?.refresh_expires_at;



  if (

    !Number.isFinite(accessExpiry) ||

    !Number.isFinite(refreshExpiry)

  ) {

    throw new Error("Missing token expiration");

  }



  await env.DB.prepare(`

    INSERT INTO tiktok_auth (

      account_id,

      access_token,

      refresh_token,

      access_expires_at,

      refresh_expires_at,

      updated_at

    )

    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)

    ON CONFLICT(account_id) DO UPDATE SET

      access_token = excluded.access_token,

      refresh_token = excluded.refresh_token,

      access_expires_at = excluded.access_expires_at,

      refresh_expires_at = excluded.refresh_expires_at,

      updated_at = CURRENT_TIMESTAMP

  `).bind(

    ACCOUNT_ID,

    access,

    refresh,

    accessExpiry,

    refreshExpiry

  ).run();

}



async function getAccessToken(env) {

  const saved = await env.DB.prepare(

    "SELECT * FROM tiktok_auth WHERE account_id = ?"

  ).bind(ACCOUNT_ID).first();



  if (!saved) {

    throw new Error("TikTok account not connected");

  }



  const now = Math.floor(Date.now() / 1000);



  if (saved.access_expires_at > now + 300) {

    return decrypt(saved.access_token, env);

  }



  if (saved.refresh_expires_at <= now + 300) {

    throw new Error("TikTok authorization expired");

  }



  const refreshToken = await decrypt(

    saved.refresh_token,

    env

  );



  const updated = await tokenRequest({

    grant_type: "refresh_token",

    refresh_token: refreshToken

  }, env);



  await saveTokens(env, updated, {

    refresh_token: refreshToken,

    refresh_expires_at: saved.refresh_expires_at

  });



  return updated.access_token;

}



async function collectVideos(env) {

  const accessToken = await getAccessToken(env);



  let cursor = null;

  let hasMore = true;

  let pages = 0;

  let count = 0;



  while (hasMore && pages < 10) {

    const requestBody = { max_count: 20 };



    if (cursor !== null) {

      requestBody.cursor = cursor;

    }



    const response = await fetch(

      "https://open.tiktokapis.com/v2/video/list/" +

      "?fields=id,title,create_time,view_count,like_count,comment_count,share_count",

      {

        method: "POST",

        headers: {

          Authorization: `Bearer ${accessToken}`,

          "Content-Type": "application/json"

        },

        body: JSON.stringify(requestBody)

      }

    );



    const result = await response.json();



    if (!response.ok || result.error?.code !== "ok") {

      throw new Error("TikTok video API failed");

    }



    const videos = result.data?.videos || [];

    const capturedAt = new Date().toISOString();



    for (const video of videos) {

      await env.DB.batch([

        env.DB.prepare(`

          INSERT INTO videos (

            video_id, title, created_at

          )

          VALUES (?, ?, ?)

          ON CONFLICT(video_id) DO UPDATE SET

            title = excluded.title,

            created_at = excluded.created_at

        `).bind(

          video.id,

          video.title || "",

          video.create_time || null

        ),



        env.DB.prepare(`

          INSERT INTO video_stats (

            video_id,

            recorded_at,

            views,

            likes,

            comments,

            shares

          )

          VALUES (?, ?, ?, ?, ?, ?)

        `).bind(

          video.id,

          capturedAt,

          video.view_count || 0,

          video.like_count || 0,

          video.comment_count || 0,

          video.share_count || 0

        )

      ]);



      count++;

    }



    hasMore = Boolean(result.data?.has_more);

    cursor = result.data?.cursor ?? null;

    pages++;



    if (hasMore && cursor === null) {

      throw new Error("Missing TikTok pagination cursor");

    }

  }



  return count;

}



// Vérification du mot de passe du dashboard*

async function isAuthorized(request, env) {

  if (!env.DASHBOARD_PASSWORD) return false;



  const header = request.headers.get("Authorization") || "";



  if (!header.startsWith("Basic ")) return false;



  let credentials;



  try {

    credentials = decoder.decode(

      fromBase64(header.slice(6))

    );

  } catch {

    return false;

  }



  const separator = credentials.indexOf(":");

  if (separator < 0) return false;



  const username = credentials.slice(0, separator);

  const password = credentials.slice(separator + 1);



  if (username !== "admin") return false;



  const expected = await crypto.subtle.digest(

    "SHA-256",

    encoder.encode(env.DASHBOARD_PASSWORD)

  );



  const received = await crypto.subtle.digest(

    "SHA-256",

    encoder.encode(password)

  );



  const a = new Uint8Array(expected);

  const b = new Uint8Array(received);



  let difference = 0;



  for (let i = 0; i < a.length; i++) {

    difference |= a[i] ^ b[i];

  }



  return difference === 0;

}



function unauthorized() {

  return new Response("Authentification requise", {

    status: 401,

    headers: {

      "WWW-Authenticate": 'Basic realm="Little Elsewhere Analytics"',

      ...HEADERS

    }

  });

}



// Dernier relevé de chaque vidéo*

async function getStats(env) {
  const result = await env.DB.prepare(`
    SELECT v.video_id, v.title, v.created_at, s.recorded_at,
           s.views, s.likes, s.comments, s.shares,
           (SELECT s2.views FROM video_stats s2
            WHERE s2.video_id = v.video_id AND s2.id <> s.id
            ORDER BY s2.recorded_at DESC, s2.id DESC LIMIT 1) AS previous_views,
           (SELECT s2.recorded_at FROM video_stats s2 WHERE s2.video_id = v.video_id AND s2.id <> s.id ORDER BY s2.recorded_at DESC, s2.id DESC LIMIT 1) AS previous_at,
           (SELECT s2.views FROM video_stats s2 WHERE s2.video_id = v.video_id AND s2.id NOT IN (s.id, (SELECT s3.id FROM video_stats s3 WHERE s3.video_id = v.video_id AND s3.id <> s.id ORDER BY s3.recorded_at DESC, s3.id DESC LIMIT 1)) ORDER BY s2.recorded_at DESC, s2.id DESC LIMIT 1) AS older_views,
           (SELECT s2.recorded_at FROM video_stats s2 WHERE s2.video_id = v.video_id AND s2.id NOT IN (s.id, (SELECT s3.id FROM video_stats s3 WHERE s3.video_id = v.video_id AND s3.id <> s.id ORDER BY s3.recorded_at DESC, s3.id DESC LIMIT 1)) ORDER BY s2.recorded_at DESC, s2.id DESC LIMIT 1) AS older_at
    FROM videos v JOIN video_stats s ON s.id = (
      SELECT s3.id FROM video_stats s3 WHERE s3.video_id = v.video_id
      ORDER BY s3.recorded_at DESC, s3.id DESC LIMIT 1
    ) ORDER BY s.views DESC, v.video_id
  `).all();
  const videos = (result.results || []).map(v => {
    const views = Number(v.views || 0), likes = Number(v.likes || 0),
          comments = Number(v.comments || 0), shares = Number(v.shares || 0);
    const parseTime = value => {
      if (!value) return NaN;
      const t = String(value).trim().replace(" ", "T");
      return Date.parse(/[zZ]$|[+-]\\d\\d:\\d\\d$/.test(t) ? t : t + "Z");
    };
    const hours = v.previous_at ? (parseTime(v.recorded_at) - parseTime(v.previous_at)) / 3600000 : 0;
    const olderHours = v.older_at && v.previous_at ? (parseTime(v.previous_at) - parseTime(v.older_at)) / 3600000 : 0;
    const gain = v.previous_views == null ? null : views - Number(v.previous_views);
    const velocity = hours > 0 && gain >= 0 ? gain / hours : null;
    const oldGain = v.older_views == null || v.previous_views == null ? null : Number(v.previous_views) - Number(v.older_views);
    const oldVelocity = olderHours > 0 && oldGain >= 0 ? oldGain / olderHours : null;
    const trend = velocity == null || oldVelocity == null || hours < 0.1 || olderHours < 0.1
      ? "insufficient" : oldVelocity < 1 && velocity < 1 ? "stable"
      : velocity > oldVelocity * 1.25 && velocity - oldVelocity >= 5 ? "accelerating"
      : velocity < oldVelocity * 0.75 && oldVelocity - velocity >= 5 ? "slowing" : "stable";
    return {...v, views, likes, comments, shares, gainViews:gain, viewsPerHour:velocity,
      trend, intervalHours:hours > 0 ? hours : null,
      engagementRate: views ? (likes + comments + shares) * 100 / views : 0};
  });
  const totals = videos.reduce((a,v) => {
    for(const k of ["views","likes","comments","shares"]) a[k] += v[k];
    return a;
  },{views:0,likes:0,comments:0,shares:0});
  const lastSync = videos.map(v=>v.recorded_at).filter(Boolean).sort().at(-1)||null;
  return {account:ACCOUNT_ID,videoCount:videos.length,totals,lastSync,videos};
}

async function getHistory(env) {
  const rows = await env.DB.prepare(`
    WITH daily_latest AS (
      SELECT date(recorded_at) AS day, video_id, views,
        ROW_NUMBER() OVER (
          PARTITION BY date(recorded_at), video_id
          ORDER BY recorded_at DESC, id DESC
        ) AS rn
      FROM video_stats
      WHERE recorded_at >= datetime('now', '-30 days')
    )
    SELECT day, SUM(views) AS views, COUNT(*) AS videos
    FROM daily_latest
    WHERE rn = 1
    GROUP BY day
    ORDER BY day ASC
  `).all();
  return {days: (rows.results || []).map(r => ({
    date: r.day, views: Number(r.views || 0), videos: Number(r.videos || 0)
  }))};
}

function dashboard() {

  return new Response(`<!doctype html>

<html lang="fr">

<head>

<meta charset="utf-8">

<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Little Elsewhere Analytics</title>

<style>

* { box-sizing: border-box; }



body {

  margin: 0;

  background: #0b1020;

  color: #f2f5ff;

  font-family: system-ui, sans-serif;

}



main {

  max-width: 1250px;

  margin: auto;

  padding: 40px 24px;
}



header {

  display: flex;

  justify-content: space-between;

  align-items: center;

  gap: 20px;

  flex-wrap: wrap;

  margin-bottom: 35px;

}



small {

  color: #86b9ff;

  letter-spacing: 2px;

  font-weight: bold;

}



h1 {

  font-size: 42px;

  margin: 8px 0;

}



h2 { margin-top: 0; }



.muted { color: #a8b5d5; }



button {

  border: 0;

  background: #327ed1;

  color: white;

  padding: 13px 20px;

  border-radius: 10px;

  cursor: pointer;

  font-weight: bold;

}



.cards {

  display: grid;

  grid-template-columns: repeat(4, minmax(0,1fr));

  gap: 16px;

}



.card, section {

  background: #151e35;

  border: 1px solid #2b3a58;

  border-radius: 16px;

  padding: 24px;

}



.card .label {

  color: #a8b5d5;

  font-size: 14px;

}



.card .value {

  font-size: 30px;

  font-weight: 800;

  margin-top: 15px;

}



section { margin-top: 20px; }



.table-wrap { overflow-x: auto; }



table {

  width: 100%;

  border-collapse: collapse;

  text-align: left;

}



th, td {

  padding: 13px;

  border-bottom: 1px solid #2b3a58;

}



th {

  color: #a8b5d5;

  font-size: 13px;

}



td { font-size: 14px; } select{background:#24324f;color:white;padding:10px;border:1px solid #415574;border-radius:8px}



a { color: #86b9ff; }



#status {

  margin-top: 12px;

  color: #a8b5d5;

}



@media(max-width: 750px) {

  .cards { grid-template-columns: repeat(2,1fr); }

  h1 { font-size: 32px; }

}



@media(max-width: 400px) {

  .cards { grid-template-columns: 1fr; }

}

</style>

</head>

<body>

<main>

<header>

  <div>

    <small>LITTLE ELSEWHERE · TIKTOK</small>

    <h1>Analytics</h1>

    <p class="muted">Suivi des performances de tes vidéos</p>

  </div>

  <button id="refresh">Actualiser l'affichage</button>

</header>



<div class="cards">

  <div class="card">

    <div class="label">Vues cumulées</div>

    <div class="value" id="views">—</div>

  </div>

  <div class="card">

    <div class="label">J'aime</div>

    <div class="value" id="likes">—</div>

  </div>

  <div class="card">

    <div class="label">Commentaires</div>

    <div class="value" id="comments">—</div>

  </div>

  <div class="card">

    <div class="label">Partages</div>

    <div class="value" id="shares">—</div>

  </div>

</div>



<nav id="dashboardTabs" aria-label="Navigation du dashboard" style="display:flex;gap:8px;flex-wrap:wrap;margin:24px 0">
<button type="button" class="tab-button active" data-tab="overview" aria-selected="true">Vue d'ensemble</button>
<button type="button" class="tab-button" data-tab="videos" aria-selected="false">Vidéos</button>
<button type="button" class="tab-button" data-tab="history" aria-selected="false">Évolution</button>
</nav>
<div class="tab-panel" data-panel="overview">
<section>

  <h2>Vue d'ensemble</h2>

  <p>Vidéos suivies : <strong id="count">—</strong></p>

  <p>Dernier relevé : <strong id="lastSync">—</strong></p>

  <p class="muted" id="status">Chargement...</p>

</section>



<section>
  <h2>À retenir</h2>
  <div id="insights" class="insight-grid"><p class="muted">Analyse des performances en cours...</p></div>
</section>
</div>
<div class="tab-panel" data-panel="history" hidden>
<section>
  <h2>Évolution des vues · 30 jours</h2>
  <p class="muted">Vues cumulées des vidéos relevées chaque jour. Les jours sans relevé ne sont pas inventés.</p>
  <canvas id="viewsChart" height="260" role="img" aria-label="Graphique des vues cumulées sur les 30 derniers jours" style="width:100%;max-width:100%;display:block"></canvas>
  <p class="muted" id="historyStatus">Chargement de l'historique...</p>
</section>

</div>
<div class="tab-panel" data-panel="videos" hidden>
<section>
  <h2>Vidéos qui progressent le plus</h2>
  <p class="muted">Top 10 des gains de vues entre les deux derniers relevés de chaque vidéo. Les intervalles peuvent différer selon les vidéos.</p>
  <div id="topGainers" aria-live="polite"><p class="muted">Chargement du classement...</p></div>
</section>

<section>

  <h2>Toutes les vidéos</h2>
  <div class="filters">
    <label>Rechercher <input id="videoSearch" type="search" placeholder="Titre ou identifiant..." autocomplete="off"></label>
    <label>Trier par <select id="sort"><option value="views">Vues</option><option value="viewsPerHour">Vues / heure</option><option value="gainViews">Gain de vues</option><option value="engagementRate">Engagement</option><option value="likes">Likes</option></select></label>
    <label>Tendance <select id="trendFilter"><option value="all">Toutes</option><option value="accelerating">En accélération</option><option value="stable">Stables</option><option value="slowing">En ralentissement</option><option value="insufficient">Données insuffisantes</option></select></label>
  </div>
  <p class="muted" id="videoResultCount">Chargement...</p>

  <div class="table-wrap">

    <table>

      <thead>

        <tr>

          <th>Vidéo</th>

          <th>Vues</th>

          <th>J'aime</th>

          <th>Commentaires</th>

          <th>Partages</th><th>Gain vues</th><th>Vues / h</th><th>Tendance</th><th>Engagement</th>

        </tr>

      </thead>

      <tbody id="videos"></tbody>

    </table>

  </div>

</section>
</div>

</main>



<script>

function showTab(tab) {
  document.querySelectorAll(".tab-panel").forEach(panel => {
    panel.hidden = panel.dataset.panel !== tab;
  });
  document.querySelectorAll("#dashboardTabs .tab-button").forEach(button => {
    const selected = button.dataset.tab === tab;
    button.classList.toggle("active",selected);
    button.setAttribute("aria-selected",String(selected));
  });
  if(tab === "history") drawHistory();
}
document.querySelectorAll("#dashboardTabs .tab-button").forEach(button => {
  button.addEventListener("click",()=>showTab(button.dataset.tab));
});
showTab("overview");

const number = n => new Intl.NumberFormat("fr-FR").format(n || 0);



async function loadStats() {

  const status = document.getElementById("status");

  status.textContent = "Chargement des statistiques...";



  try {

    const response = await fetch("/api/stats", {

      cache: "no-store"

    });



    if (!response.ok) {

      throw new Error("Erreur HTTP " + response.status);

    }



    const data = await response.json();



    for (const key of ["views", "likes", "comments", "shares"]) {

      document.getElementById(key).textContent =

        number(data.totals[key]);

    }



    document.getElementById("count").textContent =

      number(data.videoCount);



    document.getElementById("lastSync").textContent =

      data.lastSync

        ? new Date(data.lastSync).toLocaleString("fr-FR")

        : "Aucun relevé";



    window.currentVideos = data.videos;
    renderVideos();
    renderTopGainers();
    renderInsights();



    status.textContent =

      "Données chargées. L'actualisation de TikTok est gérée par le Cron Trigger.";

  } catch (error) {

    status.textContent = "Impossible de charger les statistiques : " +

      error.message;

  }

}



function renderInsights() {
  const root = document.getElementById("insights");
  root.replaceChildren();
  const all = window.currentVideos || [];
  const accelerating = all.filter(v=>v.trend==="accelerating").sort((a,b)=>(b.viewsPerHour||0)-(a.viewsPerHour||0));
  const measured = all.filter(v=>v.viewsPerHour!==null && v.viewsPerHour!==undefined);
  const top = measured.slice().sort((a,b)=>b.viewsPerHour-a.viewsPerHour)[0];
  const summaries = [
    ["Vidéos en accélération",String(accelerating.length),accelerating.length?"À surveiller dans l'onglet Vidéos":"Aucune accélération confirmée pour l'instant"],
    ["Meilleure vitesse",top?number(Math.round(top.viewsPerHour))+" vues/h":"—",top?(top.title||top.video_id):"En attente de deux relevés espacés"],
    ["Vidéos mesurables",number(measured.length)+" / "+number(all.length),"Les autres attendent des relevés supplémentaires"]
  ];
  summaries.forEach(([name,value,detail])=>{
    const card=document.createElement("article");card.className="insight-card";
    const label=document.createElement("div");label.className="muted";label.textContent=name;
    const strong=document.createElement("strong");strong.textContent=value;
    const p=document.createElement("p");p.className="muted";p.textContent=detail;
    card.append(label,strong,p);root.appendChild(card);
  });
}
function renderTopGainers() {
  const root = document.getElementById("topGainers");
  root.replaceChildren();
  const videos = (window.currentVideos || [])
    .filter(v => v.gainViews !== null && v.gainViews !== undefined && Number.isFinite(Number(v.gainViews)))
    .sort((a,b) => Number(b.gainViews)-Number(a.gainViews))
    .slice(0,10);
  if (!videos.length) {
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "Il faut au moins deux relevés par vidéo pour mesurer leur progression.";
    root.appendChild(p);
    return;
  }
  const highest = Math.max(1,...videos.map(v=>Math.max(0,Number(v.gainViews))));
  videos.forEach((video,index) => {
    const row = document.createElement("div");
    row.style.cssText = "padding:14px 0;border-bottom:1px solid #2b3a58";
    const top = document.createElement("div");
    top.style.cssText = "display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap";
    const name = document.createElement("span");
    name.style.cssText = "font-weight:600;overflow-wrap:anywhere";
    name.textContent = (index+1)+". "+(video.title || video.video_id);
    const gain = document.createElement("strong");
    const delta = Number(video.gainViews);
    gain.textContent = (delta>0?"+":"")+number(delta)+" vues";
    top.append(name,gain);
    const track = document.createElement("div");
    track.style.cssText = "height:9px;background:#263752;border-radius:8px;overflow:hidden;margin-top:10px";
    const bar = document.createElement("div");
    bar.style.cssText = "height:100%;background:#65b8ff;border-radius:8px;width:"+Math.max(0,delta)/highest*100+"%";
    track.appendChild(bar);
    row.append(top,track);
    root.appendChild(row);
  });
}

function renderVideos() {
  const tbody = document.getElementById("videos");
  tbody.replaceChildren();
  const key = document.getElementById("sort").value;
  const search = document.getElementById("videoSearch").value.trim().toLocaleLowerCase("fr");
  const trend = document.getElementById("trendFilter").value;
  const videos = (window.currentVideos || [])
    .filter(v => (!search || String(v.title || "").toLocaleLowerCase("fr").includes(search) || String(v.video_id).includes(search))
      && (trend === "all" || v.trend === trend))
    .sort((a,b) => (Number(b[key]) || 0) - (Number(a[key]) || 0));
  document.getElementById("videoResultCount").textContent = number(videos.length)+" vidéo(s) affichée(s)";
  const fragment = document.createDocumentFragment();
  for(const video of videos) {
    const tr = document.createElement("tr");
    const values = [
      video.title || video.video_id, number(video.views),number(video.likes),number(video.comments),number(video.shares),
      video.gainViews == null ? "—" : (video.gainViews > 0 ? "+" : "")+number(video.gainViews),
      video.viewsPerHour == null ? "—" : number(Math.round(video.viewsPerHour)),
      ({accelerating:"↗ Accélération",stable:"→ Stable",slowing:"↘ Ralentissement",insufficient:"À mesurer"})[video.trend] || "À mesurer",
      Number(video.engagementRate || 0).toFixed(2)+" %"
    ];
    values.forEach((value,i)=>{
      const td=document.createElement("td");td.textContent=value;
      if(i===7)td.className="trend-"+video.trend;
      tr.appendChild(td);
    });
    fragment.appendChild(tr);
  }
  tbody.appendChild(fragment);
}
async function loadHistory() {
  const label = document.getElementById("historyStatus");
  try {
    const response = await fetch("/api/history", {cache:"no-store"});
    if (!response.ok) throw new Error("HTTP " + response.status);
    const payload = await response.json();
    const days = payload.days || [];
    if (!days.length) {
      label.textContent = "Aucun relevé disponible pour les 30 derniers jours.";
      return;
    }
    const latest = days[days.length - 1];
    label.textContent = days.length === 1
      ? "Un seul jour de relevé pour l'instant. La courbe se construira avec les prochains relevés."
      : days.length + " jours de relevés · Dernier total : " + number(latest.views) + " vues · " + latest.videos + " vidéos relevées le " + latest.date;
    window.historyDays = days;
    drawHistory();
  } catch(error) {
    label.textContent = "Historique indisponible : " + error.message;
  }
}
function drawHistory() {
  const days = window.historyDays || [];
  if (!days.length) return;
  const canvas = document.getElementById("viewsChart");
  const width = Math.max(320, canvas.getBoundingClientRect().width || 700);
  const height = 260, ratio = window.devicePixelRatio || 1;
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  const left = 65, right = 16, top = 20, bottom = 42;
  const values = days.map(d => d.views);
  let min = Math.min(...values), max = Math.max(...values);
  const pad = Math.max((max-min)*0.15, max*0.02, 1);
  min = Math.max(0,min-pad); max += pad;
  const x = i => left + (width-left-right) * (days.length===1 ? 0.5 : i/(days.length-1));
  const y = v => top + (height-top-bottom)*(max-v)/(max-min);
  ctx.font = "12px system-ui"; ctx.textAlign = "right";
  for(let i=0;i<=4;i++) {
    const value = min+(max-min)*(4-i)/4, yy=y(value);
    ctx.strokeStyle="#30415f";ctx.beginPath();ctx.moveTo(left,yy);ctx.lineTo(width-right,yy);ctx.stroke();
    ctx.fillStyle="#b2bfda";ctx.fillText(new Intl.NumberFormat("fr-FR",{notation:"compact",maximumFractionDigits:1}).format(value),left-9,yy+4);
  }
  ctx.strokeStyle="#7abaff";ctx.lineWidth=3;ctx.lineJoin="round";
  ctx.beginPath();
  days.forEach((d,i)=>{if(i===0)ctx.moveTo(x(i),y(d.views));else ctx.lineTo(x(i),y(d.views));});
  ctx.stroke();
  days.forEach((d,i)=>{ctx.beginPath();ctx.arc(x(i),y(d.views),3.5,0,Math.PI*2);ctx.fillStyle="#a8d5ff";ctx.fill();});
  ctx.fillStyle="#b2bfda";ctx.textAlign="left";
  ctx.fillText(days[0].date.slice(5),left,height-14);
  ctx.textAlign="right";ctx.fillText(days[days.length-1].date.slice(5),width-right,height-14);
}
window.addEventListener("resize",drawHistory);

document.getElementById("sort").addEventListener("change",renderVideos);
document.getElementById("videoSearch").addEventListener("input",renderVideos);
document.getElementById("trendFilter").addEventListener("change",renderVideos);

document.getElementById("refresh").addEventListener(

  "click",

  loadStats

);



loadStats();
loadHistory();

setInterval(loadStats, 60000);
setInterval(loadHistory, 60000);

</script>

</body>

</html>`, {

    headers: {

      "Content-Type": "text/html; charset=utf-8",

      ...HEADERS

    }

  });

}



export default {

  async fetch(request, env) {

    const url = new URL(request.url);



    if (

      !env.DB ||

      !env.TIKTOK_CLIENT_KEY ||

      !env.TIKTOK_CLIENT_SECRET ||

      !env.TIKTOK_SESSION_SECRET ||

      !env.TIKTOK_ENCRYPTION_KEY

    ) {

      return html("<p>Configuration TikTok incomplète.</p>", 500);

    }



    if (url.pathname === "/") {

      return html(`

        <h1>Little Elsewhere Analytics</h1>

        <p><a href="/dashboard">Ouvrir mon dashboard</a></p>

        <p><a href="/login">Connecter mon compte TikTok</a></p>

      `);

    }



    if (url.pathname === "/dashboard" ||

        url.pathname === "/api/stats" ||
        url.pathname === "/api/history") {



      if (!env.DASHBOARD_PASSWORD) {

        return html(

          "<p>Ajoute le secret DASHBOARD_PASSWORD dans Cloudflare.</p>",

          503

        );

      }



      if (!(await isAuthorized(request, env))) {

        return unauthorized();

      }



      if (url.pathname === "/dashboard") {

        return dashboard();

      }



      try {

        return json(url.pathname === "/api/history" ? await getHistory(env) : await getStats(env));

      } catch (error) {

        console.error("Dashboard error:", error.message);

        return json({ error: "stats_unavailable" }, 500);

      }

    }



    if (url.pathname === "/login") {

      const state = randomHex();

      const issued = Math.floor(Date.now() / 1000);

      const payload = state + "." + issued;



      const sig = await hmac(

        payload,

        env.TIKTOK_SESSION_SECRET

      );



      const auth = new URL(

        "https://www.tiktok.com/v2/auth/authorize/"

      );



      auth.searchParams.set(

        "client_key",

        env.TIKTOK_CLIENT_KEY

      );

      auth.searchParams.set("response_type", "code");

      auth.searchParams.set("scope", SCOPES);

      auth.searchParams.set("redirect_uri", REDIRECT_URI);

      auth.searchParams.set("state", state);



      return new Response(null, {

        status: 302,

        headers: {

          Location: auth.toString(),

          "Set-Cookie":

            `tt_state=${payload}.${sig}; ` +

            "HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600",

          "Cache-Control": "no-store"

        }

      });

    }



    if (url.pathname === "/callback") {

      const finish = (message, status = 200) =>

        html(message, status, {

          "Set-Cookie": CLEAR_STATE

        });



      const saved = getCookie(request, "tt_state");

      const parts = saved?.split(".");



      if (!parts || parts.length !== 3) {

        return finish("<p>Session expirée.</p>", 400);

      }



      const [expected, issued, received] = parts;



      const calculated = await hmac(

        expected + "." + issued,

        env.TIKTOK_SESSION_SECRET

      );



      const age =

        Date.now() / 1000 - Number(issued);



      if (

        received !== calculated ||

        expected !== url.searchParams.get("state") ||

        !Number.isFinite(age) ||

        age < -30 ||

        age > 600

      ) {

        return finish(

          "<p>Vérification de sécurité échouée.</p>",

          403

        );

      }



      if (url.searchParams.has("error")) {

        return finish(

          "<p>Autorisation TikTok refusée.</p>",

          400

        );

      }



      const code = url.searchParams.get("code");



      if (!code) {

        return finish("<p>Code manquant.</p>", 400);

      }



      try {

        const token = await tokenRequest({

          code,

          grant_type: "authorization_code",

          redirect_uri: REDIRECT_URI

        }, env);



        await saveTokens(env, token);



        const count = await collectVideos(env);



        return finish(`

          <h2>Connexion réussie</h2>

          <p>Compte TikTok connecté.</p>

          <p><strong>${count} vidéos</strong> enregistrées.</p>

          <p><a href="/dashboard">Ouvrir le dashboard</a></p>

        `);

      } catch (error) {

        console.error(

          "TikTok connection failed:",

          error.message

        );



        return finish(

          "<p>Connexion ou collecte impossible.</p>",

          502

        );

      }

    }



    return html("<p>Page introuvable.</p>", 404);

  },



  async scheduled(event, env, ctx) {

    ctx.waitUntil(

      collectVideos(env).catch(error => {

        console.error(

          "TikTok synchronization failed:",

          error.message

        );

      })

    );

  }

};