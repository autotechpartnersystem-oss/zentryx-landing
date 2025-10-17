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

  // Decap cheamă /oauth?provider=github → redirecționăm spre /authorize
  if (pathname === basePath) {
    return { statusCode: 302, headers: { Location: `${baseUrl}${basePath}/authorize` }, body: "" };
  }

  // Redirect către GitHub consent
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

  // Callback: schimbăm code → token și îl trimitem părintelui
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

    // Trimitem ambele formate + „împingem” părintele pe /admin/#/
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>Authenticating…</title></head>
<body>
<script>
(function () {
  var token = ${JSON.stringify(token)};
  var parentWin = window.opener || window.parent;

  try { parentWin.postMessage('authorization:github:success:' + token, '*'); } catch(e) {}
  try { parentWin.postMessage({ token: token }, '*'); } catch(e) {}

  // „Nudge” – dacă UI-ul e încă pe ecranul de login, forțăm reload-ul dashboard-ului
  try { parentWin.location.hash = '#/'; } catch(e) {}

  setTimeout(function(){ try{ window.close(); } catch(e){} }, 50);
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
