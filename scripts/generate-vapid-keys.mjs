// Generates the two secrets push.js needs and prints the `wrangler secret put` commands to store
// them. Run this once (or whenever you want to rotate the keys):
//
//   node scripts/generate-vapid-keys.mjs
//
// The private key never leaves this output — don't commit it, and don't put it in wrangler.jsonc.

const b64uEncode = (bytes) => Buffer.from(bytes).toString("base64url");

const { publicKey, privateKey } = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"]
);

const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
const { d: privateD } = await crypto.subtle.exportKey("jwk", privateKey);

const VAPID_PUBLIC_KEY = b64uEncode(publicRaw);
const VAPID_PRIVATE_KEY = privateD; // already base64url per the JWK spec

console.log(`VAPID_PUBLIC_KEY=${VAPID_PUBLIC_KEY}`);
console.log(`VAPID_PRIVATE_KEY=${VAPID_PRIVATE_KEY}`);
console.log(`
Store these as Worker secrets (this only has to be done once — they're read at request time,
nothing needs to be redeployed afterwards):

  npx wrangler secret put VAPID_PUBLIC_KEY
    (paste ${VAPID_PUBLIC_KEY})

  npx wrangler secret put VAPID_PRIVATE_KEY
    (paste ${VAPID_PRIVATE_KEY})

Optional: VAPID_PRIVATE_KEY's counterpart, a contact address some push services log if they need to
reach you about this server (e.g. "mailto:you@example.com"). Falls back to the site's own origin
if you skip it:

  npx wrangler secret put VAPID_SUBJECT
`);
