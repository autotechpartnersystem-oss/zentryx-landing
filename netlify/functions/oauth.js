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
  const searchParams = url.searchParams;

  const json = (status, body, headers = {}) => ({
    statusCode: status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
    body: JSON.stringify(body),
  });

  // Decap pornește cu /oauth?provider=github -> redirecționează la /authorize
  if (pathname === basePath) {
    return { statusCode: 302, headers: { Location: `${baseUrl}${basePath}/authorize` }, body: "" };
  }

  // Redirect către consimțământul GitHub
  if (pathname.endsWith("/authorize")) {
    const state = random(24);
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

  // Callback: schimbă code -> token și postează mesajul pentru Decap
  if (pathname.endsWith("/callback")) {
    const code = searchParams.get("code");
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
      const htmlErr = htmlMessage(`authorization:github:error:${(data.error_description || "token_exchange_failed")}`);
      return { statusCode: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }, body: htmlErr };
    }

    // ✅ Formatul pe care îl așteaptă Decap:
    const payload = `authorization:github:success:${data.access_token}`;
    const htmlOk = htmlMessage(payload);

    return {
      statusCode: 200,
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      body: htmlOk,
    };
  }

  // Info pentru testare manuală
  return json(200, { ok: true, authorize: `${basePath}/authorize`, callback: `${basePath}/callback` });
}

// Helpers
function random(len = 24) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = ""; for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random()*chars.length)];
  return s;
}

function htmlMessage(message) {
  // Trimite mesajul către fereastra părinte și închide tab-ul
  return `<!doctype html><html><head><meta charset="utf-8"><title>Authenticating…</title></head>
  <body>
    <script>
      (function () {
        var msg = ${JSON.stringify(message)};
        try { (window.opener || window.parent).postMessage(msg, "*"); } catch(e) {}
        try { window.close(); } catch(e) {}
      })();
    </script>
    <p>You can close this window.</p>
  </body></html>`;
}
