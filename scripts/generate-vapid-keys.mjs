// Makes the key pair that lets this server send push notifications (VAPID, RFC 8292).
//
//   npm run vapid
//
// Run it once. Keep the same keys from then on: if they change, everyone who turned on
// notifications has to turn them off and on again.

import { generateKeyPairSync } from "node:crypto";

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = privateKey.export({ format: "jwk" });
const publicKey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, "base64url"), Buffer.from(jwk.y, "base64url")]).toString("base64url");

console.log(`
VAPID_PUBLIC_KEY=${publicKey}
VAPID_PRIVATE_KEY=${jwk.d}

Live site: store both as Worker secrets (once), then deploy as usual.

  npx wrangler secret put VAPID_PUBLIC_KEY      (paste the public key)
  npx wrangler secret put VAPID_PRIVATE_KEY     (paste the private key)

  Or in the Cloudflare dashboard: Workers & Pages > betachat > Settings > Variables and Secrets,
  add each one with type "Secret".

Local testing (npm run dev): put the two lines above in a file named .dev.vars in the project
folder. It is already in .gitignore.

Never commit or share the private key.
`);
