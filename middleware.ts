import { next } from "@vercel/functions";
import { createRemoteJWKSet, jwtVerify } from "jose";

/**
 * 플랫폼 런치 토큰 게이트.
 * 이 배포로 들어오는 모든 요청을 가로채어,
 * 유효한 런치 토큰으로 들어온 세션에만 콘텐츠를 허용.
 */

export const config = { runtime: "nodejs" };

const COOKIE = "eduino_launch";
const SESSION_SECONDS = 60 * 60 * 24;

const enc = new TextEncoder();

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array {
  const pad = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(pad + "=".repeat((4 - (pad.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function hmacKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(process.env.LAUNCH_SESSION_SECRET ?? ""),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** 세션 쿠키 발급 */
async function issueSession(claims: Record<string, unknown>): Promise<string> {
  const body = b64urlEncode(enc.encode(JSON.stringify(claims)));
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(),
    enc.encode(body),
  );
  return `${body}.${b64urlEncode(new Uint8Array(sig))}`;
}

/** 세션 쿠키 검증 — 서명 불일치·만료면 null */
async function readSession(
  value: string | undefined,
): Promise<Record<string, unknown> | null> {
  if (!value) return null;
  const [body, sig] = value.split(".");
  if (!body || !sig) return null;
  const ok = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(),
    b64urlDecode(sig),
    enc.encode(body),
  );
  if (!ok) return null;
  try {
    const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    if (typeof claims.exp !== "number" || claims.exp * 1000 < Date.now())
      return null;
    return claims;
  } catch {
    return null;
  }
}

/**
 * 플랫폼 공개키 목록(JWKS) — 모듈 스코프에 한 번만 만들어 재사용.
 * jose 가 kid 별로 캐시하고, 모르는 kid 가 오면 쿨다운을 두고 다시 받아온다(키 교체 대응).
 * 기본 fetch 라 커스텀 헤더·credentials 가 없어 프리플라이트가 생기지 않음 — 플랫폼 CORS 계약과 일치.
 */
let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
function launchJwks() {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(process.env.LAUNCH_JWKS_URL ?? ""), {
      cacheMaxAge: 60 * 60 * 1000,
      cooldownDuration: 30 * 1000,
    });
  }
  return jwks;
}

/** 런치 토큰 검증 */
async function verifyLaunchToken(token: string, origin: string) {
  const { payload } = await jwtVerify(token, launchJwks(), {
    issuer: process.env.LAUNCH_ISSUER,
    audience: process.env.LAUNCH_AUDIENCE || origin,
  });
  if (payload.typ !== "launch") throw new Error("unexpected token type");
  return payload;
}

/** 차단 안내 화면 — 플랫폼 재입장 화면과 같은 모양. 외부 자원 없이 인라인으로만 구성. */
function deniedPage(returnUrl: string): string {
  const cta = returnUrl
    ? `<a class="cta" href="${returnUrl}">코드로 입장하기</a>`
    : "";
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>다시 입장하려면 코드가 필요해요</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; padding: 24px;
    display: flex; align-items: center; justify-content: center;
    background: linear-gradient(rgb(250,251,254) 0%, rgb(241,242,248) 100%);
    font-family: Pretendard, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1f2536;
    /* 한국어 어절 중간 줄바꿈 방지 — 플랫폼 전역 리셋과 동일 */
    word-break: keep-all;
  }
  .card {
    width: 100%; max-width: 440px; padding: 40px;
    background: #fff; border-radius: 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08), 0 4px 16px rgba(0,0,0,.06);
    display: flex; flex-direction: column; align-items: center; gap: 20px;
    text-align: center;
  }
  h1 { margin: 0; font-size: 22px; font-weight: 700; line-height: 1.4; }
  p { margin: 0; font-size: 15px; line-height: 1.6; color: #6b7388; }
  .cta {
    display: block; width: 100%; padding: 16px; border-radius: 12px;
    background: linear-gradient(160deg, rgb(255,180,180) 0%, rgb(232,58,58) 70%, rgb(196,42,42) 100%);
    box-shadow: 0 8px 20px #ffe9e9;
    color: #fff; font-size: 16px; font-weight: 700; text-decoration: none;
  }
  .note { font-size: 13px; color: #6b7388; }
</style>
</head>
<body>
  <main class="card">
    <h1>다시 입장하려면 코드가 필요해요</h1>
    <p>콘텐츠 세션이 끝났어요. 선생님이 알려준 코드를 다시 입력하면 바로 이어서 들어갈 수 있어요.</p>
    ${cta}
    <span class="note">선생님·개인 계정은 로그인 후 자동으로 이동해요.</span>
  </main>
</body>
</html>`;
}

function denied(request: Request): Response {
  const back = process.env.LAUNCH_RETURN_URL ?? "";
  const isDocument = request.headers.get("sec-fetch-dest") === "document";
  if (!isDocument) {
    return new Response(JSON.stringify({ error: "launch_required" }), {
      status: 401,
      headers: { "content-type": "application/json", "x-gate": "blocked" },
    });
  }
  return new Response(deniedPage(back), {
    status: 403,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "x-gate": "blocked",
    },
  });
}

/** 이 배포가 외부에 노출된 주소 */
function publicOrigin(request: Request, url: URL): string {
  const host =
    request.headers.get("x-forwarded-host") ??
    request.headers.get("host") ??
    url.host;
  return `https://${host}`;
}

export default async function middleware(request: Request) {
  const url = new URL(request.url);
  const lt = url.searchParams.get("lt");

  // 진입 — 런치 토큰을 세션 쿠키로 교환
  if (lt) {
    try {
      const payload = await verifyLaunchToken(lt, publicOrigin(request, url));
      const session = await issueSession({
        sub: payload.sub,
        kit: payload.kit,
        role: payload.role,
        ctx: payload.ctx,
        exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS,
      });
      const clean = new URL(url.toString());
      clean.searchParams.delete("lt");
      return new Response(null, {
        status: 302,
        headers: {
          Location: clean.pathname + clean.search,
          "Set-Cookie": `${COOKIE}=${session}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`,
          "x-gate": "issued",
        },
      });
    } catch {
      return denied(request);
    }
  }

  const cookieHeader = request.headers.get("cookie") ?? "";
  const raw = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${COOKIE}=`))
    ?.slice(COOKIE.length + 1);

  const session = await readSession(raw);
  if (!session) return denied(request);

  return next({ headers: { "x-gate": "allowed" } });
}
