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

  // --- START route (Decap calls this with ?provider=github) ---
  if (pathname === basePath) {
    // Redirect to /authorize to kick off GitHub consent
    return {
      statusCode: 302,
      headers: { Location: `${baseUrl}${basePath}/authorize` },
      body: "",
    };
  }

  // --- AUTHORIZE: redirect user to GitHub consent ---
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

  // --- CALLBACK: exchange code for access token ---
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

    // Shape expected by Decap: { token: "<github_access_token>" }
    return json(200, { token: data.access_token }, {
      "Set-Cookie": "decap_oauth_state=deleted; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
    });
  }

  // --- Default: basic info (for manual tests) ---
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
