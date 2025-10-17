// netlify/functions/oauth.js
export async function handler(event) {
  const clientId = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;

  const host = event.headers["x-forwarded-host"] || event.headers.host;
  const proto = event.headers["x-forwarded-proto"] || "https";
  const baseUrl = `${proto}://${host}`;
  const basePath = "/.netlify/functions/oauth";
  const redirectUri = `${baseUrl}${basePath}/callback`;

  // --- CORS (safe) ---
  const ALLOW_ORIGIN = baseUrl; // rulează pe același domeniu (ex: https://www.zentryxdigital.co.uk)
  const corsHeaders = {
    "Access-Control-Allow-Origin": ALLOW_ORIGIN,
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Cache-Control": "no-store",
  };
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders };
  }

  const url = new URL(event.rawUrl || `${baseUrl}${event.path}`);
  const pathname = url.pathname;
  const qs = url.searchParams;

  const json = (status, body, headers = {}) => ({
    statusCode: status,
    headers: { "content-type": "application/json", ...corsHeaders, ...headers },
    body: JSON.stringify(body),
  });

  const htmlReply = (body) => ({
    statusCode: 200,
    headers: { "content-type": "text/html; charset=utf-8", ...corsHeaders },
    body,
  });

  // redirect /oauth -> /oauth/authorize
  if (pathname === basePath) {
    return {
      statusCode: 302,
      headers: { ...corsHeaders, Location: `${baseUrl}${basePath}/authorize` },
      body: "",
    };
  }

  // STEP 1: redirect la GitHub
  if (pathname.endsWith("/authorize")) {
    const state = rnd(24);
    const gh = new URL("https://github.com/login/oauth/authorize");
    gh.searchParams.set("client_id", clientId);
    gh.searchParams.set("redirect_uri", redirectUri);
    gh.searchParams.set("scope", "repo,user:email");
    gh.searchParams.set("state", state);

    return {
      statusCode: 302,
      headers: {
        ...corsHeaders,
        Location: gh.toString(),
        // 5 min: suficient pt roundtrip
        "Set-Cookie": `decap_oauth_state=${state}; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax`,
      },
      body: "",
    };
  }

  // STEP 2: schimbă code -> token și postează token-ul înapoi la /admin
  if (pathname.endsWith("/callback")) {
    const code = qs.get("code");
    if (!code) return json(400, { error: "missing_code" });

    const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        code,
      }),
    });

    const data = await tokenRes.json();
    const token = data && data.access_token;

    if (!token) {
      return htmlReply(msgHtml("authorization:github:error:token_exchange_failed"));
    }

    // IMPORTANT: trimitem payload-ul exact pe care Decap îl așteaptă
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Authenticating…</title></head>
<body>
<script>
(function () {
  var token = ${JSON.stringify(token)};
  var parentWin = window.opener || window.parent;

  function postTo(target) {
    try { parentWin.postMessage({ type: 'authorization:github', token: token }, target); } catch(e) {}
  }

  var noOpener = false;
  try { noOpener = !parentWin || parentWin === window; } catch(e) { noOpener = true; }

  if (noOpener) {
    // Fallback: pune token-ul în hash pentru bridge-ul din /admin/index.html
    window.location = '${baseUrl}/admin/#auth:github:success:' + encodeURIComponent(token);
  } else {
    try { parentWin.focus(); } catch(e) {}
    // Trimitem către origin-ul corect și și către '*' ca fallback
    postTo('${baseUrl}');
    postTo('*');
    // mic delay apoi închide
    setTimeout(function(){ try{ window.close(); }catch(e){} }, 80);
  }
})();
</script>
<p>You can close this window.</p>
</body></html>`;

    return htmlReply(html);
  }

  // Health check
  return json(200, { ok: true, authorize: `${basePath}/authorize`, callback: `${basePath}/callback` });
}

function rnd(len) {
  const a = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = "";
  for (let i = 0; i < len; i++) s += a[Math.floor(Math.random() * a.length)];
  return s;
}
function msgHtml(m) {
  return `<!doctype html><html><body><script>(opener||parent).postMessage(${JSON.stringify(m)},"*");</script>Error.</body></html>`;
}
