

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

    SELECT

      v.video_id,

      v.title,

      v.created_at,

      s.recorded_at,

      s.views,

      s.likes,

      s.comments,

      s.shares

    FROM videos v

    JOIN video_stats s

      ON s.id = (

        SELECT s2.id

        FROM video_stats s2

        WHERE s2.video_id = v.video_id

        ORDER BY s2.recorded_at DESC, s2.id DESC

        LIMIT 1

      )

    ORDER BY s.views DESC, v.video_id

  `).all();



  const videos = result.results || [];



  const totals = videos.reduce(

    (acc, v) => {

      acc.views += Number(v.views || 0);

      acc.likes += Number(v.likes || 0);

      acc.comments += Number(v.comments || 0);

      acc.shares += Number(v.shares || 0);

      return acc;

    },

    {

      views: 0,

      likes: 0,

      comments: 0,

      shares: 0

    }

  );



  const lastSync = videos

    .map(v => v.recorded_at)

    .filter(Boolean)

    .sort()

    .at(-1) || null;



  return {

    account: ACCOUNT_ID,

    videoCount: videos.length,

    totals,

    lastSync,

    videos

  };

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



td { font-size: 14px; }



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



<section>

  <h2>Vue d'ensemble</h2>

  <p>Vidéos suivies : <strong id="count">—</strong></p>

  <p>Dernier relevé : <strong id="lastSync">—</strong></p>

  <p class="muted" id="status">Chargement...</p>

</section>



<section>

  <h2>Performances par vidéo</h2>

  <div class="table-wrap">

    <table>

      <thead>

        <tr>

          <th>Vidéo</th>

          <th>Vues</th>

          <th>J'aime</th>

          <th>Commentaires</th>

          <th>Partages</th>

        </tr>

      </thead>

      <tbody id="videos"></tbody>

    </table>

  </div>

</section>

</main>



<script>

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



    const tbody = document.getElementById("videos");

    tbody.replaceChildren();



    for (const video of data.videos) {

      const tr = document.createElement("tr");



      const title = document.createElement("td");

      title.textContent = video.title || video.video_id;



      tr.appendChild(title);



      for (const key of ["views", "likes", "comments", "shares"]) {

        const td = document.createElement("td");

        td.textContent = number(video[key]);

        tr.appendChild(td);

      }



      tbody.appendChild(tr);

    }



    status.textContent =

      "Données chargées. L'actualisation de TikTok est gérée par le Cron Trigger.";

  } catch (error) {

    status.textContent = "Impossible de charger les statistiques : " +

      error.message;

  }

}



document.getElementById("refresh").addEventListener(

  "click",

  loadStats

);



loadStats();

setInterval(loadStats, 60000);

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

        url.pathname === "/api/stats") {



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

        return json(await getStats(env));

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