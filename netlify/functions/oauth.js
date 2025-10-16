// netlify/functions/oauth.js
export async function handler(event) {
  const clientId = process.env.OAUTH_CLIENT_ID;
  const clientSecret = process.env.OAUTH_CLIENT_SECRET;

  const host = event.headers["x-forwarded-host"] || event.headers.host;
  const proto = event.headers["x-forwarded-proto"] || "https";
  const baseUrl = `${proto}://${host}`;
  const redirectUri = `${baseUrl}/.netlify/functions/oauth/callback`;

  const url = new URL(event.rawUrl || `${baseUrl}${event.path}`);
  const pathname = url.pathname;
  const searchParams = url.searchParams;

  const json = (status, body, headers = {}) => ({
    statusCode: status,
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

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
        "Set-Cookie": `decap_state=${state}; Path=/; Max-Age=300; HttpOnly; Secure; SameSite=Lax`,
      },
      body: "",
    };
  }

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

    return json(200, { token: data.access_token }, {
      "Cache-Control": "no-store",
      "Set-Cookie": "decap_state=deleted; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
    });
  }

  return json(200, {
    ok: true,
    authorize: "/.netlify/functions/oauth/authorize",
    callback: "/.netlify/functions/oauth/callback",
  });
}

function random(len = 24) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = ""; for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random()*chars.length)];
  return s;
}
