const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const STATE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_SCOPE = "repo";
const CALLBACK_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "text/html; charset=UTF-8",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';",
};

export default {
  async fetch(request, env) {
    try {
      assertEnv(env);

      const url = new URL(request.url);

      if (request.method !== "GET") {
        return new Response("Method Not Allowed", {
          status: 405,
          headers: { Allow: "GET" },
        });
      }

      if (url.pathname === "/auth") {
        return handleAuth(request, env, url);
      }

      if (url.pathname === "/callback") {
        return handleCallback(env, url);
      }

      return new Response("Decap CMS GitHub OAuth proxy is running.", {
        status: 200,
        headers: {
          "Cache-Control": "no-store",
          "Content-Type": "text/plain; charset=UTF-8",
          "X-Content-Type-Options": "nosniff",
        },
      });
    } catch (error) {
      return new Response("OAuth proxy configuration error.", {
        status: 500,
        headers: {
          "Cache-Control": "no-store",
          "Content-Type": "text/plain; charset=UTF-8",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }
  },
};

function assertEnv(env) {
  const required = ["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET", "REDIRECT_URI"];

  for (const key of required) {
    if (!env[key] || typeof env[key] !== "string") {
      throw new Error(`Missing required environment variable: ${key}`);
    }
  }
}

async function handleAuth(request, env, url) {
  const provider = url.searchParams.get("provider") || "github";

  if (provider !== "github") {
    return new Response("Unsupported provider.", {
      status: 400,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "text/plain; charset=UTF-8",
      },
    });
  }

  const origin = getCmsOrigin(request, url.searchParams.get("site_id"));

  if (!origin) {
    return renderCallback("error", {
      error: "missing_origin",
      error_description: "Unable to determine the CMS origin for the callback.",
    });
  }

  const state = await createSignedState(
    {
      origin,
      nonce: crypto.randomUUID(),
      issuedAt: Date.now(),
    },
    env.GITHUB_CLIENT_SECRET,
  );

  const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL);
  authorizeUrl.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", env.REDIRECT_URI);
  authorizeUrl.searchParams.set("scope", sanitizeScope(url.searchParams.get("scope")));
  authorizeUrl.searchParams.set("state", state);

  return Response.redirect(authorizeUrl.toString(), 302);
}

async function handleCallback(env, url) {
  const provider = "github";
  const githubError = url.searchParams.get("error");
  const githubErrorDescription = url.searchParams.get("error_description");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!state) {
    return renderCallback("error", {
      error: "missing_state",
      error_description: "Missing OAuth state.",
    });
  }

  let decodedState;

  try {
    decodedState = await verifySignedState(state, env.GITHUB_CLIENT_SECRET);
  } catch (error) {
    return renderCallback("error", {
      error: "invalid_state",
      error_description: "OAuth state validation failed.",
    });
  }

  if (githubError) {
    return renderCallback(
      "error",
      {
        error: githubError,
        error_description: githubErrorDescription || "GitHub authorization failed.",
      },
      decodedState.origin,
    );
  }

  if (!code) {
    return renderCallback(
      "error",
      {
        error: "missing_code",
        error_description: "GitHub did not return an authorization code.",
      },
      decodedState.origin,
    );
  }

  let tokenResponse;
  let tokenPayload;

  try {
    tokenResponse = await fetch(GITHUB_TOKEN_URL, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "User-Agent": "tobulaelektra-decacms-oauth",
      },
      body: JSON.stringify({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: env.REDIRECT_URI,
      }),
    });

    tokenPayload = await tokenResponse.json();
  } catch (error) {
    return renderCallback(
      "error",
      {
        error: "token_exchange_failed",
        error_description: "GitHub token exchange request failed.",
      },
      decodedState.origin,
    );
  }

  if (!tokenResponse.ok || tokenPayload.error || !tokenPayload.access_token) {
    return renderCallback(
      "error",
      {
        error: tokenPayload.error || "token_exchange_failed",
        error_description:
          tokenPayload.error_description ||
          "GitHub token exchange failed.",
      },
      decodedState.origin,
    );
  }

  return renderCallback(
    "success",
    {
      token: tokenPayload.access_token,
      provider,
    },
    decodedState.origin,
  );
}

function getCmsOrigin(request, siteId) {
  const referer = request.headers.get("Referer");

  if (referer) {
    try {
      return new URL(referer).origin;
    } catch (error) {
      // Ignore malformed referrers and continue to site_id fallback.
    }
  }

  if (!siteId) {
    return null;
  }

  try {
    if (/^https?:\/\//i.test(siteId)) {
      return new URL(siteId).origin;
    }

    const host = siteId.trim().replace(/\/+$/, "");
    const protocol =
      host.startsWith("localhost") || host.startsWith("127.0.0.1")
        ? "http:"
        : "https:";

    return new URL(`${protocol}//${host}`).origin;
  } catch (error) {
    return null;
  }
}

function sanitizeScope(scope) {
  if (!scope) {
    return DEFAULT_SCOPE;
  }

  return /^[a-z0-9, _:-]+$/i.test(scope) ? scope : DEFAULT_SCOPE;
}

async function createSignedState(payload, secret) {
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = await signValue(encodedPayload, secret);

  return `${encodedPayload}.${signature}`;
}

async function verifySignedState(state, secret) {
  const [encodedPayload, signature] = state.split(".");

  if (!encodedPayload || !signature) {
    throw new Error("Malformed OAuth state.");
  }

  const expectedSignature = await signValue(encodedPayload, secret);

  if (!timingSafeEqual(signature, expectedSignature)) {
    throw new Error("Invalid OAuth state signature.");
  }

  const payload = JSON.parse(base64UrlDecode(encodedPayload));

  if (!payload.origin || !payload.nonce || !payload.issuedAt) {
    throw new Error("Incomplete OAuth state payload.");
  }

  if (Date.now() - payload.issuedAt > STATE_TTL_MS) {
    throw new Error("Expired OAuth state.");
  }

  return payload;
}

async function signValue(value, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(value),
  );

  return arrayBufferToBase64Url(signature);
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }

  let mismatch = 0;

  for (let index = 0; index < left.length; index += 1) {
    mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return mismatch === 0;
}

function renderCallback(status, content, targetOrigin = "*") {
  const payload = `authorization:github:${status}:${JSON.stringify(content)}`;
  const html = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>OAuth Callback</title>
  </head>
  <body>
    <script>
      const payload = ${JSON.stringify(payload)};
      const targetOrigin = ${JSON.stringify(targetOrigin)};

      function receiveMessage(event) {
        if (targetOrigin !== "*" && event.origin !== targetOrigin) {
          return;
        }

        window.opener.postMessage(payload, event.origin);
        window.removeEventListener("message", receiveMessage, false);
        window.close();
      }

      if (!window.opener) {
        document.body.textContent = "Authentication completed. You can close this window.";
      } else {
        window.addEventListener("message", receiveMessage, false);
        window.opener.postMessage("authorizing:github", targetOrigin);
        setTimeout(() => {
          document.body.textContent = "Waiting for Decap CMS response. You can close this window if login has already completed.";
        }, 3000);
      }
    </script>
  </body>
</html>`;

  return new Response(html, {
    status: status === "success" ? 200 : 400,
    headers: CALLBACK_HEADERS,
  });
}

function base64UrlEncode(value) {
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));

  return atob(normalized + padding);
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
