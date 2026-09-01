# Demo data for screenshots

`WebhookHandler.java` — `verifyUnsafe` (dot-equals) and
`verifyUnsafeBytes` (Arrays.equals) flagged; `verifySafe`
(MessageDigest.isEqual) not flagged.

## How to get the screenshot

1. `./gradlew runIde` from `jwt-webhook-timing-safe-companion`, open
   this `demo/` folder as the project.
2. Full Screen, open `WebhookHandler.java` — warnings should appear on
   the `.equals(...)` and `Arrays.equals(...)` calls but not on
   `MessageDigest.isEqual(...)`.
3. Screenshot with all three methods visible, save into
   `jwt-webhook-timing-safe-companion/docs/screenshots/`. Close the
   sandbox.
