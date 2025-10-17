// netlify/functions/oauth.js
export async function handler(event) {
  const clientId = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;

  const host = event.headers["x-forwarded-host"] || event.headers.host;
  const proto = event.headers["x-forwarded-proto"] || "https";
  const baseUrl = `${proto}://${host}`;
  const basePath = "/.netlify/functions/oauth";
  const redirectUri = `${baseUrl}${basePath}/callback`;

  const url = new URL(event.rawUrl || `${baseUrl}${event.path}`);
  const pathname = url.pathname;
  const qs = url.searchParams;

  const json = (status, body, headers = {}) => ({
    statusCode: status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
    body: JSON.stringify(body),
  });

  if (pathname === basePath) {
    return { statusCode: 302, headers: { Location: `${baseUrl}${basePath}/authorize` }, body: "" };
  }

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
        Location: gh.toString(),
        "Set-Cookie": `decap_oauth_state=${state}; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax`,
      },
      body: "",
    };
  }

  if (pathname.endsWith("/callback")) {
    const code = qs.get("code");
    if (!code) return json(400, { error: "Missing code" });

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
    if (!data.access_token) {
      return htmlReply(msgHtml(`authorization:github:error:${data.error_description || "token_exchange_failed"}`));
    }

    const token = data.access_token;

    // HTML care încearcă postMessage; dacă opener e null, face fallback pe redirect spre /admin cu token în hash
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Authenticating…</title></head>
<body>
<script>
(function () {
  var token = ${JSON.stringify(token)};
  var parentWin = window.opener || window.parent;

  function sendAllTargets() {
    var targets = [ (parentWin && parentWin.location ? parentWin.location.origin : '${baseUrl}'), '*' ];
    try { parentWin.focus(); } catch(e) {}
    try { targets.forEach(function(t){ parentWin.postMessage('authorization:github:success:' + token, t); }); } catch(e) {}
    try { targets.forEach(function(t){ parentWin.postMessage({ token: token }, t); }); } catch(e) {}
  }

  // dacă nu avem opener (unele browsere îl taie), facem fallback prin redirect pe /admin cu token-ul în hash
  var noOpener = false;
  try { noOpener = !parentWin || parentWin === window; } catch(e) { noOpener = true; }

  if (noOpener) {
    window.location = '${baseUrl}/admin/#auth:github:success:' + encodeURIComponent(token);
  } else {
    sendAllTargets();
    setTimeout(function(){ try{ window.close(); }catch(e){} }, 80);
  }
})();
</script>
<p>You can close this window.</p>
</body></html>`;

    return { statusCode: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }, body: html };
  }

  return json(200, { ok: true, authorize: `${basePath}/authorize`, callback: `${basePath}/callback` });
}

function rnd(len){const a="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";let s="";for(let i=0;i<len;i++)s+=a[Math.floor(Math.random()*a.length)];return s;}
function msgHtml(m){return `<!doctype html><html><body><script>(opener||parent).postMessage(${JSON.stringify(m)},"*");</script>Error.</body></html>`}
function htmlReply(body){return { statusCode: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control":"no-store" }, body }; }
