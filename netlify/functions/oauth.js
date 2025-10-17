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

  // --- START (Decap apelează /oauth?provider=github) ---
  if (pathname === basePath) {
    return {
      statusCode: 302,
      headers: { Location: `${baseUrl}${basePath}/authorize` },
      body: "",
    };
  }

  // --- AUTHORIZE: către consimțământul GitHub ---
  if (pathname.endsWith("/authorize")) {
    const state = cryptoRandomString(24);
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

  // --- CALLBACK: schimbă code -> token și trimite-l înapoi la /admin ---
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
    if (!data.access_token) return json(500, { error: "Token exchange failed", details: data });

    // Trimite tokenul către fereastra părinte (admin) și închide tab-ul
    const html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Authenticating…</title></head>
<body>
<script>
(function () {
  var token = ${JSON.stringify(data.access_token)};
  try {
    (window.opener || window.parent).postMessage({ token: token }, window.location.origin);
  } catch (e) {
    try { (window.opener || window.parent).postMessage({ token: token }, "*"); } catch (_) {}
  }
  window.close();
})();
</script>
<p>You can close this window.</p>
</body></html>`;

    return {
      statusCode: 200,
      headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      body: html,
    };
  }

  // --- Info de test ---
  return json(200, {
    ok: true,
    authorize: `${basePath}/authorize`,
    callback: `${basePath}/callback`,
  });
}

// Helpers
function cryptoRandomString(len = 24) {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let out = "";
  for (let i = 0; i < len; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}
