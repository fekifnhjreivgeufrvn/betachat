import { DurableObject } from "cloudflare:workers";
import { pushConfigured, parseSubscription, sendPush } from "./push.js";

const MAX_TEXT = 500;
const HISTORY_LIMIT = 50; // messages sent to someone who just joined
const KEEP_MESSAGES = 500; // messages stored per room before old ones are deleted
const MIN_GAP_MS = 400; // minimum time between messages from one connection

// Accounts
const COOKIE = "betachat_session";
const SESSION_MS = 30 * 24 * 60 * 60 * 1000; // stay logged in for 30 days
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;
const RESERVED_NAMES = new Set(["admin", "administrator", "system", "root", "moderator", "mod", "support", "betachat"]);
const MIN_ACCOUNT_PASSWORD = 8;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const MAX_LOGIN_FAILS_IP = 10; // wrong logins from one IP per window...
const MAX_LOGIN_FAILS_USER = 15; // ...and against one account (from anywhere) per window
const REGISTER_WINDOW_MS = 60 * 60 * 1000;
const MAX_REGISTRATIONS_IP = 10; // accounts created from one IP per hour

// Profile pictures. The page shrinks every picture to 256 x 256 (about 10-30 KB) before uploading;
// the server re-checks all of this itself instead of trusting the page.
const MAX_AVATAR_BYTES = 128 * 1024;
const MAX_AVATAR_PX = 512;
const AVATAR_WINDOW_MS = 60 * 60 * 1000; // as long as REGISTER_WINDOW_MS, the longest window `bump` keeps
const MAX_AVATAR_CHANGES = 20; // uploads per account per hour
const AVATAR_NOTICE_GAP_MS = 1000; // "my picture changed" notices from one connection go out at most this often

// Typing indicator
const TYPING_GAP_MS = 1000; // "still typing" refreshes from one connection go out at most this often

// Push notifications to people who are away (the browser side is in public/sw.js; the sending is in push.js)
const PUSH_SUB_GAP_MS = 1000; // "turn on notifications for this device" requests from one connection are handled at most this often
const MAX_PUSH_PER_USER = 5; // devices one person can have notifications on for, per room (a new one replaces their oldest)
const MAX_PUSH_PER_ROOM = 40; // each push is one outgoing request, and a Worker on the free plan may make 50 per event
const PUSH_TTL_S = 4 * 60 * 60; // if a phone is off or offline, the push service keeps a message this long
const PUSH_BODY_CHARS = 140;

// Set by the Worker after it has checked the login cookie. Room objects trust it
// because only the Worker can reach them; the Worker overwrites whatever the client sent.
const USER_HEADER = "X-Betachat-User";
const ROOM_HEADER = "X-Betachat-Room"; // likewise: the room name, which a Durable Object can't read from its own id

// Private rooms
const MIN_PASSWORD = 6;
const MAX_PASSWORD = 128;
const PBKDF2_ITERATIONS = 100000; // the most Cloudflare Workers allows
const MAX_FAILS = 5; // wrong passwords allowed from one IP...
const LOCK_MS = 10 * 60 * 1000; // ...before that IP is locked out of the room for 10 minutes

const OPEN = 1; // WebSocket readyState for "open"
const encoder = new TextEncoder();

function cleanRoom(value) {
  return (
    (value || "general")
      .toLowerCase()
      .replace(/[^a-z0-9-]/g, "")
      .slice(0, 32) || "general"
  );
}

function sameOrigin(request, url) {
  const origin = request.headers.get("Origin");
  if (!origin) return true; // non-browser clients
  try {
    return new URL(origin).host === url.host;
  } catch {
    return false;
  }
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
  });
}

function getCookie(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

// HttpOnly keeps the token out of reach of page scripts; SameSite=Lax keeps other sites from using it.
function sessionCookie(value, maxAgeSeconds, secure) {
  return `${COOKIE}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
}

// ---- Password hashing (PBKDF2 via Web Crypto) ------------------------------
const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
const fromB64 = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    256
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, PBKDF2_ITERATIONS);
  return { salt: toB64(salt), hash: toB64(hash), iter: PBKDF2_ITERATIONS };
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---- Uploaded pictures -----------------------------------------------------
// Reads a request body, giving up (null) as soon as it is bigger than `max` bytes.
async function readBytes(request, max) {
  if (Number(request.headers.get("Content-Length")) > max) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

// Works out what an image really is, and how many pixels wide and tall, from its own header,
// without decoding it. Only JPEG, PNG and still WebP are accepted; anything else returns null.
// (The size matters: a tiny file can still decode into a huge bitmap in someone's browser.)
function sniffImage(b) {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const text = (at, len) => String.fromCharCode(...b.subarray(at, at + len));

  // PNG: 8-byte signature, then the IHDR chunk starts with the width and height
  if (b.length >= 24 && b[0] === 0x89 && text(1, 3) === "PNG" && b[4] === 0x0d && b[5] === 0x0a &&
      b[6] === 0x1a && b[7] === 0x0a && text(12, 4) === "IHDR") {
    return { type: "image/png", width: view.getUint32(16), height: view.getUint32(20) };
  }

  // JPEG: walk the segments until the frame header (SOF), which holds the size
  if (b.length > 4 && b[0] === 0xff && b[1] === 0xd8) {
    let i = 2;
    while (i + 4 <= b.length) {
      if (b[i] !== 0xff) return null;
      const marker = b[i + 1];
      if (marker === 0xff) { i++; continue; } // padding
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) { i += 2; continue; } // no length field
      if (marker === 0xd9 || marker === 0xda) return null; // reached the image data with no size found
      const length = view.getUint16(i + 2);
      if (length < 2) return null;
      const isFrame = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
      if (isFrame) {
        if (i + 9 > b.length) return null;
        return { type: "image/jpeg", height: view.getUint16(i + 5), width: view.getUint16(i + 7) };
      }
      i += 2 + length;
    }
    return null;
  }

  // WebP: RIFF container; lossy (VP8), lossless (VP8L) and extended (VP8X) store the size differently
  if (b.length >= 30 && text(0, 4) === "RIFF" && text(8, 4) === "WEBP") {
    const kind = text(12, 4);
    if (kind === "VP8 " && b[23] === 0x9d && b[24] === 0x01 && b[25] === 0x2a) {
      return {
        type: "image/webp",
        width: view.getUint16(26, true) & 0x3fff,
        height: view.getUint16(28, true) & 0x3fff,
      };
    }
    if (kind === "VP8L" && b[20] === 0x2f) {
      const bits = view.getUint32(21, true);
      return { type: "image/webp", width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
    }
    if (kind === "VP8X" && !(b[20] & 0x02)) { // 0x02 = animated
      const u24 = (at) => b[at] | (b[at + 1] << 8) | (b[at + 2] << 16);
      return { type: "image/webp", width: u24(24) + 1, height: u24(27) + 1 };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Worker
//   /api/*  register, log in, log out, who am I, profile pictures
//   /ws     the chat socket; requires a login and is routed to the right room
// Everything else (index.html etc.) is served from ./public by Workers Assets.
// The room password is never put in the URL; it is sent inside the socket.
// ---------------------------------------------------------------------------
const userDirectory = (env) => env.USERS.get(env.USERS.idFromName("global"));

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected a WebSocket connection", { status: 426 });
      }
      if (!sameOrigin(request, url)) {
        return new Response("Forbidden", { status: 403 });
      }

      const token = getCookie(request, COOKIE);
      const session = token ? await userDirectory(env).whoami(token) : null;
      if (!session) return new Response("Log in first", { status: 401 });

      const room = cleanRoom(url.searchParams.get("room"));
      const stub = env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName(room));
      const headers = new Headers(request.headers);
      headers.set(USER_HEADER, session.name); // set, not append: a client-supplied value is discarded
      headers.set(ROOM_HEADER, room);
      return stub.fetch(new Request(request, { headers }));
    }

    if (url.pathname.startsWith("/api/")) return handleApi(request, env, url);

    return new Response("Not found", { status: 404 });
  },
};

async function handleApi(request, env, url) {
  const users = userDirectory(env);
  const secure = url.protocol === "https:"; // plain http only happens in local development

  if (url.pathname === "/api/me" && request.method === "GET") {
    const token = getCookie(request, COOKIE);
    const session = token ? await users.whoami(token) : null;
    return session
      ? json({ username: session.name, avatar: session.avatar })
      : json({ error: "Not logged in." }, 401);
  }

  // Anyone logged in can look at anyone's picture (the name is the lookup key)
  if (url.pathname.startsWith("/api/avatar/") && request.method === "GET") return getAvatar(request, env, url);

  if (url.pathname === "/api/avatar" && (request.method === "POST" || request.method === "DELETE")) {
    // A cross-site page can't send these without a preflight, and the cookie is SameSite=Lax as well.
    if (!sameOrigin(request, url)) return json({ error: "Forbidden." }, 403);
    return request.method === "POST" ? uploadAvatar(request, env) : removeAvatar(request, env);
  }

  // The public half of the push key pair, which the browser needs to subscribe. Absent = push is not set up.
  if (url.pathname === "/api/push-key" && request.method === "GET") {
    return pushConfigured(env)
      ? json({ key: env.VAPID_PUBLIC_KEY })
      : json({ error: "Notifications are not set up on this server." }, 404);
  }

  if (request.method !== "POST") return json({ error: "Not found." }, 404);
  // Cross-site pages can't send JSON without a preflight, and the cookie is SameSite=Lax as well.
  if (!sameOrigin(request, url)) return json({ error: "Forbidden." }, 403);
  if (!(request.headers.get("Content-Type") || "").includes("application/json")) {
    return json({ error: "Expected JSON." }, 415);
  }

  if (url.pathname === "/api/logout") {
    const token = getCookie(request, COOKIE);
    if (token) await users.logout(token);
    return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0, secure) });
  }

  if (url.pathname === "/api/register" || url.pathname === "/api/login") {
    let body = null;
    try {
      const text = await request.text();
      if (text.length <= 2048) body = JSON.parse(text);
    } catch {}
    if (!body || typeof body.username !== "string" || typeof body.password !== "string") {
      return json({ error: "Enter a username and password." }, 400);
    }
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const result =
      url.pathname === "/api/register"
        ? await users.register(body.username, body.password, ip)
        : await users.login(body.username, body.password, ip);
    if (!result.ok) return json({ error: result.message, code: result.code }, result.status);
    return json({ username: result.name, avatar: result.avatar }, 200, {
      "Set-Cookie": sessionCookie(result.token, SESSION_MS / 1000, secure),
    });
  }

  return json({ error: "Not found." }, 404);
}

// ---- Profile pictures ------------------------------------------------------
// Served from our own origin, so everything about them is locked down: the stored type is the one
// found by sniffing (never the client's claim), and browsers are told not to guess or run anything.
async function getAvatar(request, env, url) {
  let key = "";
  try {
    key = decodeURIComponent(url.pathname.slice("/api/avatar/".length)).toLowerCase();
  } catch {}
  const result = await userDirectory(env).avatar(getCookie(request, COOKIE), key);
  if (!result.ok) {
    // "No picture" is cached briefly so a room full of people without one doesn't cost a request each time
    const cache = result.status === 404 ? "private, max-age=30" : "no-store";
    return new Response(null, { status: result.status, headers: { "Cache-Control": cache } });
  }
  const etag = `"${result.updated}"`;
  const headers = {
    "Content-Type": result.type,
    "Cache-Control": "private, no-cache", // always check, but a 304 makes that nearly free
    ETag: etag,
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; sandbox",
  };
  if (request.headers.get("If-None-Match") === etag) return new Response(null, { status: 304, headers });
  return new Response(result.data, { headers });
}

async function uploadAvatar(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token) return json({ error: "Log in first." }, 401);
  if (!(request.headers.get("Content-Type") || "").startsWith("image/")) {
    return json({ error: "Expected an image.", code: "bad_image" }, 415);
  }
  const bytes = await readBytes(request, MAX_AVATAR_BYTES);
  if (!bytes) return json({ error: "That picture is too big.", code: "too_large" }, 413);

  const info = sniffImage(bytes);
  if (!info || !info.width || !info.height || info.width > MAX_AVATAR_PX || info.height > MAX_AVATAR_PX) {
    return json(
      { error: `Use a JPEG, PNG or WebP picture up to ${MAX_AVATAR_PX} x ${MAX_AVATAR_PX} pixels.`, code: "bad_image" },
      415
    );
  }
  const result = await userDirectory(env).setAvatar(token, info.type, bytes);
  if (!result.ok) return json({ error: result.message, code: result.code }, result.status);
  return json({ avatar: result.version });
}

async function removeAvatar(request, env) {
  const result = await userDirectory(env).clearAvatar(getCookie(request, COOKIE));
  if (!result.ok) return json({ error: result.message, code: result.code }, result.status);
  return json({ avatar: null });
}

// ---------------------------------------------------------------------------
// Durable Object: the account directory (one instance for the whole app).
// Holds users, login sessions and the counters that slow down password guessing.
// ---------------------------------------------------------------------------
const fail = (code, message, status = 400) => ({ ok: false, code, message, status });
const DUMMY_SALT = new Uint8Array(16); // lets a login for an unknown username cost as much as a real one

export class UserDirectory extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        key     TEXT PRIMARY KEY,  -- lowercase username: what makes names unique
        name    TEXT NOT NULL,     -- as typed at registration; this is what other people see
        salt    TEXT NOT NULL,
        hash    TEXT NOT NULL,
        iter    INTEGER NOT NULL,
        created INTEGER NOT NULL
      )
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,  -- SHA-256 of the cookie value; the token itself is never stored
        key        TEXT NOT NULL,
        expires    INTEGER NOT NULL
      )
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS avatars (
        key     TEXT PRIMARY KEY,  -- lowercase username; at most one picture per account
        type    TEXT NOT NULL,     -- image/jpeg, image/png or image/webp, as found by sniffImage
        data    BLOB NOT NULL,
        updated INTEGER NOT NULL   -- when it was set; doubles as the ETag and the cache-buster
      )
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS throttle (
        bucket TEXT PRIMARY KEY,
        count  INTEGER NOT NULL,
        since  INTEGER NOT NULL  -- start of the current window
      )
    `);
  }

  async register(username, password, ip) {
    const now = Date.now();
    username = username.trim();
    if (!USERNAME_RE.test(username)) {
      return fail("bad_username", "Usernames are 3 to 20 letters, numbers, underscores or hyphens.");
    }
    const key = username.toLowerCase();
    if (RESERVED_NAMES.has(key)) return fail("reserved", "That username is reserved.", 409);
    if (password.length < MIN_ACCOUNT_PASSWORD || password.length > MAX_PASSWORD) {
      return fail(
        "weak_password",
        `Use a password of ${MIN_ACCOUNT_PASSWORD} to ${MAX_PASSWORD} characters.`
      );
    }

    const bucket = `register:${ip}`;
    if (this.blockedFor(bucket, MAX_REGISTRATIONS_IP, REGISTER_WINDOW_MS, now) > 0) {
      return fail("throttled", "Too many accounts created from this network. Try again later.", 429);
    }
    this.bump(bucket, REGISTER_WINDOW_MS, now);

    if (this.userRow(key)) return fail("taken", "That username is taken.", 409);
    const record = await hashPassword(password);
    // Hashing was async, so someone else may have taken the name meanwhile.
    // Re-check and insert with no await in between.
    if (this.userRow(key)) return fail("taken", "That username is taken.", 409);
    this.sql.exec(
      "INSERT INTO users (key, name, salt, hash, iter, created) VALUES (?, ?, ?, ?, ?, ?)",
      key,
      username,
      record.salt,
      record.hash,
      record.iter,
      now
    );
    return this.openSession(key, username, now);
  }

  async login(username, password, ip) {
    const now = Date.now();
    const key = username.trim().toLowerCase();
    const ipBucket = `login-ip:${ip}`;
    const userBucket = `login-user:${key}`;

    const wait = Math.max(
      this.blockedFor(ipBucket, MAX_LOGIN_FAILS_IP, LOGIN_WINDOW_MS, now),
      this.blockedFor(userBucket, MAX_LOGIN_FAILS_USER, LOGIN_WINDOW_MS, now)
    );
    if (wait > 0) {
      const minutes = Math.ceil(wait / 60000);
      return fail(
        "locked",
        `Too many failed logins. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
        429
      );
    }

    const user = password.length <= MAX_PASSWORD ? this.userRow(key) : null;
    // Unknown usernames still pay for a hash, so timing doesn't reveal which names exist.
    const hash = await derive(
      password.slice(0, MAX_PASSWORD),
      user ? fromB64(user.salt) : DUMMY_SALT,
      user ? user.iter : PBKDF2_ITERATIONS
    );
    if (!user || !safeEqual(hash, fromB64(user.hash))) {
      this.bump(ipBucket, LOGIN_WINDOW_MS, now);
      if (user) this.bump(userBucket, LOGIN_WINDOW_MS, now);
      return fail("bad_login", "Incorrect username or password.", 401);
    }

    // Only the account's own counter is cleared: clearing the IP's would let someone
    // reset it by logging in to an account of their own between guesses.
    this.sql.exec("DELETE FROM throttle WHERE bucket = ?", userBucket);
    return this.openSession(user.key, user.name, now);
  }

  async whoami(token) {
    if (typeof token !== "string" || token.length > 128) return null;
    const row = this.sql
      .exec(
        `SELECT u.key AS key, u.name AS name, a.updated AS avatar FROM sessions s
         JOIN users u ON u.key = s.key
         LEFT JOIN avatars a ON a.key = u.key
         WHERE s.token_hash = ? AND s.expires > ?`,
        await sha256Hex(token),
        Date.now()
      )
      .toArray()[0];
    return row ? { key: row.key, name: row.name, avatar: row.avatar ?? null } : null;
  }

  async logout(token) {
    if (typeof token !== "string" || token.length > 128) return;
    this.sql.exec("DELETE FROM sessions WHERE token_hash = ?", await sha256Hex(token));
  }

  async openSession(key, name, now) {
    this.sql.exec("DELETE FROM sessions WHERE expires < ?", now);
    const token = randomToken();
    this.sql.exec(
      "INSERT INTO sessions (token_hash, key, expires) VALUES (?, ?, ?)",
      await sha256Hex(token),
      key,
      now + SESSION_MS
    );
    return { ok: true, name, token, avatar: this.avatarVersion(key) };
  }

  // ---- Profile pictures ---------------------------------------------------
  avatarVersion(key) {
    const row = this.sql.exec("SELECT updated FROM avatars WHERE key = ?", key).toArray()[0];
    return row ? row.updated : null;
  }

  async avatar(token, key) {
    if (!(await this.whoami(token))) return { ok: false, status: 401 };
    const row =
      typeof key === "string" && key.length <= 32
        ? this.sql.exec("SELECT type, data, updated FROM avatars WHERE key = ?", key).toArray()[0]
        : null;
    if (!row) return { ok: false, status: 404 };
    return { ok: true, type: row.type, data: row.data, updated: row.updated };
  }

  async setAvatar(token, type, data) {
    const session = await this.whoami(token);
    if (!session) return fail("unauthorized", "Log in first.", 401);
    const now = Date.now();
    const bucket = `avatar:${session.key}`;
    if (this.blockedFor(bucket, MAX_AVATAR_CHANGES, AVATAR_WINDOW_MS, now) > 0) {
      return fail("throttled", "You've changed your picture too many times. Try again later.", 429);
    }
    this.bump(bucket, AVATAR_WINDOW_MS, now);
    this.sql.exec(
      `INSERT INTO avatars (key, type, data, updated) VALUES (?, ?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET type = excluded.type, data = excluded.data, updated = excluded.updated`,
      session.key,
      type,
      data,
      now
    );
    return { ok: true, version: now };
  }

  async clearAvatar(token) {
    const session = await this.whoami(token);
    if (!session) return fail("unauthorized", "Log in first.", 401);
    this.sql.exec("DELETE FROM avatars WHERE key = ?", session.key);
    return { ok: true };
  }

  userRow(key) {
    return this.sql.exec("SELECT key, name, salt, hash, iter FROM users WHERE key = ?", key).toArray()[0];
  }

  // ---- Attempt counters (fixed windows) -----------------------------------
  blockedFor(bucket, max, windowMs, now) {
    const row = this.sql.exec("SELECT count, since FROM throttle WHERE bucket = ?", bucket).toArray()[0];
    if (!row || now - row.since >= windowMs || row.count < max) return 0;
    return row.since + windowMs - now;
  }

  bump(bucket, windowMs, now) {
    this.sql.exec("DELETE FROM throttle WHERE since < ?", now - REGISTER_WINDOW_MS); // the longest window
    this.sql.exec(
      `INSERT INTO throttle (bucket, count, since) VALUES (?, 1, ?)
       ON CONFLICT(bucket) DO UPDATE SET
         count = CASE WHEN ? - since >= ? THEN 1 ELSE count + 1 END,
         since = CASE WHEN ? - since >= ? THEN ? ELSE since END`,
      bucket,
      now,
      now,
      windowMs,
      now,
      windowMs,
      now
    );
  }
}

// ---------------------------------------------------------------------------
// Durable Object: one instance per room. Holds the open WebSockets, the room
// settings (owner, public or private + password hash) and the message history.
//
// Who someone is comes from their login, never from the socket: the Worker
// passes the verified username in a header, and the room stamps it on every
// message. Clients cannot choose a name or claim to be someone else.
//
// Protocol
//   client -> server  {type:"join", password?}   must be sent first
//   client -> server  {type:"message", text}
//   client -> server  {type:"set_password", password}   owner only; signs everyone else out
//   client -> server  {type:"remove_password"}          owner only; makes the room public
//   client -> server  {type:"delete_room"}              owner only; wipes the room
//   client -> server  {type:"avatar_updated"}           "I changed my picture"; the room tells everyone to look again
//   client -> server  {type:"typing", typing:true|false}   started/kept typing, or stopped
//   client -> server  {type:"away", away:true|false}       this tab is hidden / visible again
//   client -> server  {type:"push_subscribe", subscription}   "notify this device about this room when I'm away"
//   client -> server  {type:"push_unsubscribe", endpoint}     stop that
//   server -> client  {type:"joined", private, owner}   then "history", "presence"
//   server -> client  {type:"join_error", code, message}   socket is closed
//   server -> client  {type:"room_updated", private, message}
//   server -> client  {type:"kicked" | "room_deleted", by?, message}   socket is closed
//   server -> client  {type:"settings_error", message}
//   server -> client  {type:"avatar", cid, v}           that person's picture changed; v is its version (0 = none)
//   server -> client  {type:"typing", cid, name, typing}   someone else started or stopped typing
//   server -> client  {type:"message" | "presence" | "error", ...}
// A socket receives nothing about the room until its join succeeds.
// ---------------------------------------------------------------------------
export class ChatRoom extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.avatarWaiting = new Set(); // sockets with a "picture changed" notice waiting out the gap
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        id   INTEGER PRIMARY KEY AUTOINCREMENT,
        cid  TEXT    NOT NULL,  -- sender's lowercase username (rows from before accounts: a random browser id)
        name TEXT    NOT NULL,
        text TEXT    NOT NULL,
        ts   INTEGER NOT NULL
      )
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS room (
        id      INTEGER PRIMARY KEY CHECK (id = 1),
        private INTEGER NOT NULL,
        salt    TEXT,
        hash    TEXT,
        iter    INTEGER,
        owner   TEXT,  -- lowercase username of the creator; NULL for rooms made before accounts
        created INTEGER NOT NULL
      )
    `);
    // Rooms created before accounts existed have no owner column yet
    const hasOwner = this.sql
      .exec("PRAGMA table_info(room)")
      .toArray()
      .some((column) => column.name === "owner");
    if (!hasOwner) this.sql.exec("ALTER TABLE room ADD COLUMN owner TEXT");

    // Devices to notify about this room when their owner has it closed. One row per browser
    // subscription; `cid` is the lowercase username it belongs to.
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS push_subs (
        endpoint TEXT PRIMARY KEY,
        cid      TEXT    NOT NULL,
        p256dh   TEXT    NOT NULL,
        auth     TEXT    NOT NULL,
        created  INTEGER NOT NULL
      )
    `);

    // Wrong-password counters per IP; rows are deleted once they are older than LOCK_MS
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS auth_attempts (
        ip    TEXT PRIMARY KEY,
        fails INTEGER NOT NULL,
        last  INTEGER NOT NULL
      )
    `);
  }

  async fetch(request) {
    const user = request.headers.get(USER_HEADER);
    if (!user) return new Response("Log in first", { status: 401 });

    const { 0: client, 1: server } = new WebSocketPair();

    // Hibernation API: the object can be evicted from memory while sockets
    // stay connected, so idle rooms cost almost nothing.
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({
      authed: false,
      sid: crypto.randomUUID(), // tells one socket from another, e.g. "everyone except me"
      user, // as registered, for display
      key: user.toLowerCase(), // identity
      ip: request.headers.get("CF-Connecting-IP") || "unknown",
      room: request.headers.get(ROOM_HEADER) || "",
      origin: new URL(request.url).origin, // the address people use for this site (push services want a contact for the sender)
      away: false, // the page says so when its tab is hidden
    });

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, raw) {
    if (typeof raw !== "string" || raw.length > 4096) return;

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return;
    }
    if (!data || typeof data !== "object") return;

    if (data.type === "join") {
      await this.join(ws, typeof data.password === "string" ? data.password : "");
      return;
    }

    const meta = ws.deserializeAttachment() || {};
    if (!meta.authed || !meta.key) return;

    switch (data.type) {
      case "message":
        return this.postMessage(ws, meta, data);
      case "set_password":
        return this.setPassword(ws, meta, data.password);
      case "remove_password":
        return this.removePassword(ws, meta);
      case "delete_room":
        return this.deleteRoom(ws, meta);
      case "avatar_updated":
        return this.avatarUpdated(ws, meta);
      case "typing":
        if (data.typing === true || data.typing === false) this.typing(ws, meta, data.typing);
        return;
      case "away":
        if (typeof data.away === "boolean" && data.away !== !!meta.away) ws.serializeAttachment({ ...meta, away: data.away });
        return;
      case "push_subscribe":
        return this.pushSubscribe(ws, meta, data.subscription);
      case "push_unsubscribe":
        if (typeof data.endpoint === "string" && data.endpoint.length <= 1000) {
          this.sql.exec("DELETE FROM push_subs WHERE endpoint = ? AND cid = ?", data.endpoint, meta.key);
        }
        return;
    }
  }

  // Typing is only ever passed on, never stored, so it costs nothing while a room is idle.
  // Who is typing comes from the login, not from the client. To everyone else, someone counts as
  // typing from their first "true" until a "false", their next message, or their socket closing; the
  // page also drops anyone it hasn't heard from in a few seconds, so a lost "false" can't stick.
  // A "true" repeated within TYPING_GAP_MS is skipped (the page only refreshes every few seconds), and
  // a "false" from someone who isn't marked as typing is ignored, so neither can be used to flood the room.
  typing(ws, meta, on) {
    const now = Date.now();
    if (on) {
      if (meta.typing && now - (meta.lastTyping || 0) < TYPING_GAP_MS) return;
      ws.serializeAttachment({ ...meta, typing: true, lastTyping: now });
    } else {
      if (!meta.typing) return;
      ws.serializeAttachment({ ...meta, typing: false });
    }
    this.broadcast({ type: "typing", cid: meta.key, name: meta.user, typing: on }, meta.sid);
  }

  // The picture itself lives in the account directory and is fetched over HTTP; this only tells the
  // room to look again. Both the person (`cid`) and the version (`v`) come from the server, not from
  // the client, so nobody can announce a change for someone else, and repeating a notice changes
  // nothing: clients ignore a version they already have.
  // Notices from one connection go out at most once per AVATAR_NOTICE_GAP_MS. One that comes too soon
  // is held back rather than dropped, and only one is ever held: it reads the latest state when it
  // fires, so it covers any further requests made while it waited.
  async avatarUpdated(ws, meta) {
    const wait = (meta.lastAvatar || 0) + AVATAR_NOTICE_GAP_MS - Date.now();
    if (wait > 0) {
      if (this.avatarWaiting.has(meta.sid)) return;
      this.avatarWaiting.add(meta.sid);
      try {
        await new Promise((resolve) => setTimeout(resolve, wait));
      } finally {
        this.avatarWaiting.delete(meta.sid);
      }
    }
    try {
      ws.serializeAttachment({ ...(ws.deserializeAttachment() || meta), lastAvatar: Date.now() });
    } catch {
      return; // the socket closed while the notice was waiting
    }
    const version = await this.env.USERS.get(this.env.USERS.idFromName("global")).avatarVersion(meta.key);
    this.broadcast({ type: "avatar", cid: meta.key, v: version ?? 0 });
  }

  async postMessage(ws, meta, data) {
    const text = String(data.text ?? "").trim().slice(0, MAX_TEXT);
    if (!text) return;

    // Simple per-connection rate limit
    const now = Date.now();
    if (meta.last && now - meta.last < MIN_GAP_MS) {
      ws.send(
        JSON.stringify({ type: "error", message: "You're sending messages too quickly." })
      );
      return;
    }
    ws.serializeAttachment({ ...meta, last: now, typing: false }); // the message itself ends "typing"

    // The sender is whoever is logged in on this socket, whatever the client claims
    const { id } = this.sql
      .exec(
        "INSERT INTO messages (cid, name, text, ts) VALUES (?, ?, ?, ?) RETURNING id",
        meta.key,
        meta.user,
        text,
        now
      )
      .one();

    // Keep only the most recent messages
    this.sql.exec("DELETE FROM messages WHERE id <= ?", id - KEEP_MESSAGES);

    this.broadcast({
      type: "message",
      message: { id, cid: meta.key, name: meta.user, text, ts: now },
    });

    // Everyone connected has it now; tell the people who aren't looking
    await this.pushToAway(meta, text);
  }

  // ---- Notifications for people who are away --------------------------------
  // Someone with a stored subscription gets a push if they are not watching this room: no open
  // connection at all, or only tabs that have reported themselves hidden. (A phone that suspends a
  // page may leave its socket looking open for a while, which is why "hidden" counts as away.)
  // The sender never gets one for their own message.
  async pushSubscribe(ws, meta, input) {
    if (!pushConfigured(this.env)) return;
    const now = Date.now();
    if (meta.lastPushSub && now - meta.lastPushSub < PUSH_SUB_GAP_MS) return;
    ws.serializeAttachment({ ...meta, lastPushSub: now });

    const sub = await parseSubscription(input);
    if (!sub) return this.settingsError(ws, "Notifications couldn't be set up on this device.");

    const known = this.sql.exec("SELECT cid FROM push_subs WHERE endpoint = ?", sub.endpoint).toArray()[0];
    if (!known) {
      const mine = this.sql.exec("SELECT COUNT(*) AS n FROM push_subs WHERE cid = ?", meta.key).one().n;
      if (mine >= MAX_PUSH_PER_USER) {
        // Their oldest device makes room for this one
        this.sql.exec(
          "DELETE FROM push_subs WHERE endpoint IN (SELECT endpoint FROM push_subs WHERE cid = ? ORDER BY created LIMIT ?)",
          meta.key,
          mine - MAX_PUSH_PER_USER + 1
        );
      }
      const total = this.sql.exec("SELECT COUNT(*) AS n FROM push_subs").one().n;
      if (total >= MAX_PUSH_PER_ROOM) {
        return this.settingsError(ws, "Too many people have notifications on for this room right now.");
      }
    }
    // An address that was someone else's (a shared device, a new login) becomes this person's
    this.sql.exec(
      `INSERT INTO push_subs (endpoint, cid, p256dh, auth, created) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(endpoint) DO UPDATE SET cid = excluded.cid, p256dh = excluded.p256dh, auth = excluded.auth, created = excluded.created`,
      sub.endpoint,
      meta.key,
      sub.p256dh,
      sub.auth,
      now
    );
  }

  async pushToAway(meta, text) {
    try {
      if (!pushConfigured(this.env)) return;
      const subject = this.env.VAPID_SUBJECT || meta.origin;
      if (!subject) return;

      const subs = this.sql.exec("SELECT endpoint, cid, p256dh, auth FROM push_subs WHERE cid != ?", meta.key).toArray();
      if (!subs.length) return;

      const watching = new Set();
      for (const socket of this.liveSockets()) {
        const info = socket.deserializeAttachment() || {};
        if (!info.away) watching.add(info.key);
      }
      const targets = subs.filter((sub) => !watching.has(sub.cid));
      if (!targets.length) return;

      const chars = Array.from(text);
      const payload = {
        title: `${meta.user} in #${meta.room}`,
        body: chars.length > PUSH_BODY_CHARS ? `${chars.slice(0, PUSH_BODY_CHARS - 1).join("")}…` : text,
        room: meta.room,
        tag: `betachat:${meta.room}`,
      };

      const outcomes = await Promise.allSettled(
        targets.map(async (sub) => {
          const result = await sendPush(this.env, sub, payload, { subject, ttl: PUSH_TTL_S });
          if (result.gone) this.sql.exec("DELETE FROM push_subs WHERE endpoint = ?", sub.endpoint); // they cancelled it
          else if (!result.ok) console.warn("push refused", new URL(sub.endpoint).host, result.status, result.detail);
          return result;
        })
      );
      const failed = outcomes.filter((o) => o.status === "rejected");
      for (const o of failed) console.warn("push failed", String(o.reason));
      console.log(`push: ${targets.length} away, ${outcomes.filter((o) => o.status === "fulfilled" && o.value.ok).length} delivered to the push service`);
    } catch (err) {
      console.warn("push error", String(err)); // a broken push must never break chat
    }
  }

  async webSocketClose(ws) {
    try {
      this.typing(ws, ws.deserializeAttachment() || {}, false); // leaving mid-sentence
    } catch {}
    try {
      ws.close(1000, "closing");
    } catch {}
    this.broadcastPresence();
  }

  async webSocketError(ws) {
    try {
      this.typing(ws, ws.deserializeAttachment() || {}, false);
    } catch {}
    this.broadcastPresence();
  }

  // ---- Joining ------------------------------------------------------------
  async join(ws, password) {
    const meta = ws.deserializeAttachment() || {};
    if (meta.authed) return;
    const ip = meta.ip || "unknown";
    const now = Date.now();

    const wait = this.lockedFor(ip, now);
    if (wait > 0) {
      const minutes = Math.ceil(wait / 60000);
      return this.reject(
        ws,
        "locked",
        `Too many wrong passwords. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`
      );
    }

    let config = this.getConfig();
    let created = false;

    if (!config) {
      // First person in this room decides whether it is public or private, and owns it.
      let record = null;
      if (password) {
        if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) {
          return this.reject(
            ws,
            "weak_password",
            `Use a password of ${MIN_PASSWORD} to ${MAX_PASSWORD} characters.`
          );
        }
        record = await hashPassword(password);
      }
      // Hashing was async, so someone else may have created the room meanwhile.
      // Re-check and create with no await in between.
      config = this.getConfig();
      if (!config) {
        config = this.createRoom(record, meta.key);
        created = true;
      }
    }

    const isOwner = !!config.owner && config.owner === meta.key;

    if (config.private && !created && !isOwner) {
      // (The owner is let in without the password: they are already proven by their login,
      // and this is how they get back in to reset a password they have forgotten.)
      if (!password) {
        return this.reject(ws, "auth_required", "This room is private. Enter its password to join.");
      }
      if (!(await this.checkPassword(password, config))) {
        this.recordFail(ip, now);
        return this.reject(ws, "auth_failed", "That password is incorrect.");
      }
      // The owner may have changed the password while that check was running.
      const latest = this.getConfig();
      if (!latest || latest.hash !== config.hash) {
        return this.reject(ws, "auth_failed", "The room's password just changed. Try again.");
      }
      this.clearFails(ip);
    } else if (!config.private && password) {
      // Never let someone believe a room is private when it is not.
      return this.reject(
        ws,
        "room_public",
        "This room already exists and is public. Choose a different room name to make a private one."
      );
    }

    const current = ws.deserializeAttachment() || {};
    ws.serializeAttachment({ ...current, authed: true });

    const history = this.sql
      .exec(
        "SELECT id, cid, name, text, ts FROM messages ORDER BY id DESC LIMIT ?",
        HISTORY_LIMIT
      )
      .toArray()
      .reverse();
    ws.send(JSON.stringify({ type: "joined", private: !!config.private, owner: isOwner }));
    ws.send(JSON.stringify({ type: "history", messages: history }));
    this.broadcastPresence();
  }

  reject(ws, code, message) {
    try {
      ws.send(JSON.stringify({ type: "join_error", code, message }));
      ws.close(1008, "join rejected");
    } catch {}
  }

  // ---- Owner actions --------------------------------------------------------
  isOwner(meta) {
    const config = this.getConfig();
    return !!config && !!config.owner && config.owner === meta.key;
  }

  settingsError(ws, message) {
    ws.send(JSON.stringify({ type: "settings_error", message }));
  }

  async setPassword(ws, meta, password) {
    if (!this.isOwner(meta)) return this.settingsError(ws, "Only the room's owner can do that.");
    if (typeof password !== "string" || password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) {
      return this.settingsError(
        ws,
        `Use a password of ${MIN_PASSWORD} to ${MAX_PASSWORD} characters.`
      );
    }
    const record = await hashPassword(password);
    if (!this.isOwner(meta)) return; // the room was deleted while the password was being hashed

    this.sql.exec(
      "UPDATE room SET private = 1, salt = ?, hash = ?, iter = ? WHERE id = 1",
      record.salt,
      record.hash,
      record.iter
    );
    // Everyone else was let in by the old password (or by the room being public):
    // sign them out so only people who get the new password stay.
    this.sql.exec("DELETE FROM push_subs WHERE cid != ?", meta.key); // signed out, so no more notifications either
    this.closeOthers(meta.sid, {
      type: "kicked",
      message: `${meta.user} set a new password for this room. Enter it to rejoin.`,
    });
    ws.send(
      JSON.stringify({
        type: "room_updated",
        private: true,
        message: "Password saved. Everyone else was signed out of the room.",
      })
    );
    this.broadcastPresence();
  }

  removePassword(ws, meta) {
    if (!this.isOwner(meta)) return this.settingsError(ws, "Only the room's owner can do that.");
    this.sql.exec("UPDATE room SET private = 0, salt = NULL, hash = NULL, iter = NULL WHERE id = 1");
    this.broadcast({
      type: "room_updated",
      private: false,
      message: `${meta.user} removed the password. Anyone can join this room now.`,
    });
  }

  deleteRoom(ws, meta) {
    if (!this.isOwner(meta)) return this.settingsError(ws, "Only the room's owner can do that.");
    // Wipe first, then tell everyone. With no room row and no messages, the next person
    // to join this name starts a brand new room and becomes its owner.
    this.sql.exec("DELETE FROM messages");
    this.sql.exec("DELETE FROM room");
    this.sql.exec("DELETE FROM auth_attempts");
    this.sql.exec("DELETE FROM push_subs");
    this.closeOthers(null, { type: "room_deleted", by: meta.user, message: `${meta.user} deleted this room.` });
  }

  // Send a final message to every socket except the one with id `exceptSid`, then close them.
  closeOthers(exceptSid, payload) {
    const message = JSON.stringify(payload);
    for (const socket of this.ctx.getWebSockets()) {
      const info = socket.deserializeAttachment() || {};
      if (exceptSid && info.sid === exceptSid) continue;
      try {
        socket.send(message);
        socket.close(1008, payload.type);
      } catch {}
    }
  }

  // ---- Room settings ------------------------------------------------------
  getConfig() {
    let row = this.sql
      .exec("SELECT private, salt, hash, iter, owner FROM room WHERE id = 1")
      .toArray()[0];
    if (!row) {
      // A room that already has history from before private rooms existed stays public.
      const hasHistory = this.sql.exec("SELECT 1 AS x FROM messages LIMIT 1").toArray().length > 0;
      if (hasHistory) row = this.createRoom(null, null);
    }
    return row || null;
  }

  createRoom(record, owner) {
    this.sql.exec(
      "INSERT OR IGNORE INTO room (id, private, salt, hash, iter, owner, created) VALUES (1, ?, ?, ?, ?, ?, ?)",
      record ? 1 : 0,
      record ? record.salt : null,
      record ? record.hash : null,
      record ? record.iter : null,
      owner,
      Date.now()
    );
    return this.sql
      .exec("SELECT private, salt, hash, iter, owner FROM room WHERE id = 1")
      .toArray()[0];
  }

  async checkPassword(password, config) {
    if (password.length > MAX_PASSWORD) return false;
    const hash = await derive(password, fromB64(config.salt), config.iter || PBKDF2_ITERATIONS);
    return safeEqual(hash, fromB64(config.hash));
  }

  // ---- Wrong-password lockout (per IP, per room) --------------------------
  lockedFor(ip, now) {
    const row = this.sql
      .exec("SELECT fails, last FROM auth_attempts WHERE ip = ?", ip)
      .toArray()[0];
    if (!row || row.fails < MAX_FAILS) return 0;
    return Math.max(0, row.last + LOCK_MS - now);
  }

  recordFail(ip, now) {
    this.sql.exec("DELETE FROM auth_attempts WHERE last < ?", now - LOCK_MS);
    this.sql.exec(
      `INSERT INTO auth_attempts (ip, fails, last) VALUES (?, 1, ?)
       ON CONFLICT(ip) DO UPDATE SET fails = fails + 1, last = ?`,
      ip,
      now,
      now
    );
  }

  clearFails(ip) {
    this.sql.exec("DELETE FROM auth_attempts WHERE ip = ?", ip);
  }

  // ---- Broadcasting (only to sockets that have joined) --------------------
  liveSockets() {
    return this.ctx
      .getWebSockets()
      .filter((s) => s.readyState === OPEN && (s.deserializeAttachment() || {}).authed);
  }

  broadcastPresence() {
    this.broadcast({ type: "presence", count: this.liveSockets().length });
  }

  // `exceptSid`: skip the socket that caused this (it already knows)
  broadcast(payload, exceptSid = null) {
    const message = JSON.stringify(payload);
    for (const socket of this.liveSockets()) {
      if (exceptSid && (socket.deserializeAttachment() || {}).sid === exceptSid) continue;
      try {
        socket.send(message);
      } catch {}
    }
  }
}
