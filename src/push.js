// Web Push for Cloudflare Workers, built on the Web Crypto API only (no dependencies).
//
//   VAPID   (RFC 8292)  proves to the push service that a message comes from this server.
//   Encryption (RFC 8291, "aes128gcm")  only the recipient's browser can read the text. Apple,
//                       Google and Mozilla just carry it and never see what it says.
//
// Settings (Worker secrets; generate them with `node scripts/generate-vapid-keys.mjs`):
//   VAPID_PUBLIC_KEY    65-byte uncompressed P-256 public key, base64url. The browser needs it too.
//   VAPID_PRIVATE_KEY   32-byte private scalar, base64url. Never leaves the server.
//   VAPID_SUBJECT       optional; a mailto: or https: contact for the push services.
//                       Defaults to this site's own address.

const encoder = new TextEncoder();

// ---- Small helpers ---------------------------------------------------------
export function b64uEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(text) {
  const b64 = String(text).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export const pushConfigured = (env) => !!(env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY);

// ---- Which addresses we are willing to POST to ------------------------------
// A subscription's address is chosen by the client, so without a check anyone could make this server
// send requests to any URL. Only the real push services are allowed.
const PUSH_HOSTS = [
  "fcm.googleapis.com", // Chrome, Edge, Samsung Internet, Android
  "push.services.mozilla.com", // Firefox
  "push.apple.com", // Safari on Mac, iPhone and iPad
  "notify.windows.com", // Edge on Windows
];

export function isPushEndpoint(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username || url.password) return false;
  if (url.port && url.port !== "443") return false;
  const host = url.hostname.toLowerCase();
  return PUSH_HOSTS.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
}

// Checks a subscription object from a browser (`subscription.toJSON()`). Returns the parts we keep,
// or null if anything is off. Never trusts the shape it is given.
export async function parseSubscription(input) {
  if (!input || typeof input !== "object") return null;
  const { endpoint, keys } = input;
  if (typeof endpoint !== "string" || endpoint.length > 1000 || !isPushEndpoint(endpoint)) return null;
  if (!keys || typeof keys.p256dh !== "string" || typeof keys.auth !== "string") return null;
  if (keys.p256dh.length > 100 || keys.auth.length > 40) return null;
  try {
    const p256dh = b64uDecode(keys.p256dh);
    const auth = b64uDecode(keys.auth);
    if (p256dh.length !== 65 || p256dh[0] !== 4 || auth.length !== 16) return null;
    // Importing also checks that the point really is on the P-256 curve
    await crypto.subtle.importKey("raw", p256dh, { name: "ECDH", namedCurve: "P-256" }, false, []);
  } catch {
    return null;
  }
  return { endpoint, p256dh: keys.p256dh, auth: keys.auth };
}

// ---- Encryption (RFC 8291 + RFC 8188) ---------------------------------------
async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
}

const RECORD_SIZE = 4096;
const MAX_PLAINTEXT = 3993; // what fits in one record, and what every push service must accept

// `fixed` is only for tests: it pins the random salt and the sender's key pair so the output can be
// compared with the worked example in RFC 8291.
export async function encryptPayload(uaPublicB64, authB64, plaintext, fixed = {}) {
  if (plaintext.length > MAX_PLAINTEXT) throw new Error("push payload too large");
  const uaPublic = b64uDecode(uaPublicB64);
  const authSecret = b64uDecode(authB64);
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);

  let asPrivate, asPublic;
  if (fixed.ephemeral) {
    asPrivate = fixed.ephemeral.privateKey;
    asPublic = fixed.ephemeral.publicRaw;
  } else {
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    asPrivate = pair.privateKey;
    asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  }
  const salt = fixed.salt || crypto.getRandomValues(new Uint8Array(16));

  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asPrivate, 256));
  const keyInfo = concat(encoder.encode("WebPush: info\0"), uaPublic, asPublic);
  const ikm = await hkdf(authSecret, sharedSecret, keyInfo, 32);
  const cek = await hkdf(salt, ikm, encoder.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, encoder.encode("Content-Encoding: nonce\0"), 12);

  const aesKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, concat(plaintext, new Uint8Array([2]))) // 0x02 ends the only record
  );

  // Header: salt (16) + record size (4) + key id length (1) + sender public key (65)
  const header = new Uint8Array(16 + 4 + 1 + 65);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, RECORD_SIZE);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return concat(header, sealed);
}

// ---- VAPID (RFC 8292) -------------------------------------------------------
let signingKey = null; // { pub, priv, key }: the imported private key, reused between messages
const authCache = new Map(); // push service origin -> { header, expires }

async function getSigningKey(env) {
  if (signingKey && signingKey.pub === env.VAPID_PUBLIC_KEY && signingKey.priv === env.VAPID_PRIVATE_KEY) {
    return signingKey.key;
  }
  const pub = b64uDecode(env.VAPID_PUBLIC_KEY);
  if (pub.length !== 65 || pub[0] !== 4) throw new Error("VAPID_PUBLIC_KEY must be an uncompressed P-256 public key (base64url)");
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: "EC", crv: "P-256", x: b64uEncode(pub.slice(1, 33)), y: b64uEncode(pub.slice(33)), d: env.VAPID_PRIVATE_KEY },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  signingKey = { pub: env.VAPID_PUBLIC_KEY, priv: env.VAPID_PRIVATE_KEY, key };
  authCache.clear();
  return key;
}

// One signed token per push service, good for 12 hours (the limit is 24)
export async function vapidAuthorization(env, audience, subject) {
  const now = Math.floor(Date.now() / 1000);
  const cached = authCache.get(audience);
  if (cached && cached.subject === subject && cached.expires - now > 3600) return cached.header;

  const key = await getSigningKey(env);
  const expires = now + 12 * 3600;
  const part = (object) => b64uEncode(encoder.encode(JSON.stringify(object)));
  const signingInput = `${part({ typ: "JWT", alg: "ES256" })}.${part({ aud: audience, exp: expires, sub: subject })}`;
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(signingInput)));
  const header = `vapid t=${signingInput}.${b64uEncode(signature)}, k=${env.VAPID_PUBLIC_KEY}`;
  authCache.set(audience, { header, expires, subject });
  return header;
}

// ---- Sending ----------------------------------------------------------------
// Returns { ok, status, gone, detail }. `gone` means the browser has cancelled this subscription
// (404 or 410), so the caller should forget it.
export async function sendPush(env, subscription, payload, { subject, ttl = 4 * 3600 } = {}) {
  const body = await encryptPayload(subscription.p256dh, subscription.auth, encoder.encode(JSON.stringify(payload)));
  const authorization = await vapidAuthorization(env, new URL(subscription.endpoint).origin, subject);
  const res = await fetch(subscription.endpoint, {
    method: "POST",
    headers: {
      Authorization: authorization,
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: String(ttl),
    },
    body,
    signal: AbortSignal.timeout(8000),
  });
  let detail = "";
  try {
    const text = await res.text(); // always read it so the connection is released
    if (!res.ok) detail = text.slice(0, 200);
  } catch {}
  return { ok: res.ok, status: res.status, gone: res.status === 404 || res.status === 410, detail };
}
