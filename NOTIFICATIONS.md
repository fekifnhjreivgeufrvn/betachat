# Notifications

betachat can notify people when a message arrives while they have it closed. There are four layers,
and only the last one needs setup.

| Layer | Needs | Works on |
|---|---|---|
| Unread count in the tab title, e.g. `(3) #general` | nothing | everywhere |
| Sound | the **Alerts** button turned on | everywhere the tab is still alive |
| Notification while the page is open | Alerts on + allow notifications | desktop, Android |
| **Push: notification when betachat is closed** | the server keys below + Alerts on | desktop, Android, iPhone/iPad (Home Screen app only) |

## One-time setup for push

1. Make the key pair (once; keep using the same one):

   ```
   npm run vapid
   ```

2. Store both values as Worker **secrets**, then deploy as usual:

   ```
   npx wrangler secret put VAPID_PUBLIC_KEY
   npx wrangler secret put VAPID_PRIVATE_KEY
   ```

   Or in the Cloudflare dashboard: Workers & Pages > betachat > Settings > Variables and Secrets >
   Add, type **Secret**. Secrets survive deployments from GitHub Actions.

3. Optional: `VAPID_SUBJECT`, a contact push services can use (`mailto:you@example.com` or an
   `https://` address). If unset, the site's own address is used.

Until the keys exist, `/api/push-key` answers 404 and the page quietly falls back to the first three
layers. Nothing breaks.

**Local testing:** put the same two lines in a file named `.dev.vars` (already git-ignored) and run
`npm run dev`. Browsers only allow push on `localhost` or HTTPS.

**Don't change the keys later.** Everyone who turned notifications on would have to turn Alerts off
and on again.

## How it works

- Turning **Alerts** on asks the browser for permission, subscribes the device with the browser's push
  service (Apple, Google or Mozilla), and hands that subscription to the room you're in.
- A room keeps a list of subscribed devices. When a message is posted, everyone in the list who is not
  watching the room gets a push. "Not watching" means no open connection, or only tabs that have said
  they're hidden (a phone can freeze a page without closing its connection, so hidden counts as away).
  The sender never gets a push for their own message.
- The message is encrypted for the receiving browser (RFC 8291); Apple, Google and Mozilla only carry
  it. The server signs each request with your private key (VAPID, RFC 8292).
- Notifications follow the room you're in: switching rooms stops notifications from the old one, and
  the page reopens on the last room you used. Logging out cancels the device's subscription.
- Changing a private room's password removes everyone else's subscriptions along with their access.

Limits: 5 devices per person per room, 40 devices per room (each push is one outgoing request, and a
Worker on the free plan may make 50 per event). A push service that says a subscription is gone
(404/410) has it deleted automatically.

## iPhone and iPad

Apple only supports web push for a site **added to the Home Screen and opened from there** (iOS/iPadOS
16.4 or later). In a Safari tab there is no push at all. The page shows a dismissible tip on iPhone and
iPad explaining this, and the Alerts button points to it.

To add it: Safari > Share (in iOS 26, tap the ••• button first if you don't see it) > **Add to Home
Screen**, leave "Open as Web App" on, then open betachat from its icon and turn on Alerts. The
permission prompt has to come from a tap on the button, which is how the page does it.

## Troubleshooting

- **No notification on an iPhone.** Is it opened from the Home Screen icon (not Safari)? Is Alerts
  on, and did you allow notifications? Check Settings > Notifications > betachat.
- **`npx wrangler tail` while sending a message** shows a line such as `push: 1 away, 1 delivered to
  the push service`. `push refused ... 403` usually means the keys are wrong or were changed;
  `410` is a cancelled subscription and is cleaned up automatically.
- **Alerts only promises notifications "while betachat is open":** the server has no push keys yet
  (step 2), or the browser can't do push.
