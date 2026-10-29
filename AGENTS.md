# Reality Proxy Kit

- Read `docs/design.md` for the accepted v0.1 scope and `docs/acceptance.md` for actual evidence. Decisions are not test results.
- This checkout is independent of any production deployment. Never discover or use production SSH credentials as test targets.
- All generated secrets inside the checkout belong under `private/`; never print or commit them. Examples use reserved addresses and domains.
- The reviewed core is fixed by `manifests/core-candidate.json`. Do not replace it with an official or panel-downloaded core. Upgrades require a separate design and compatibility validation.
- General URI, QR and URI subscriptions omit `fp`/`fingerprint`; dedicated client profiles retain required explicit client fields. Do not modify a user's separate routing profile.
- Chain routes have fixed meanings and deny by default. No entry-direct fallback, automatic failover, automatic new protocol, or reuse of retired route numbers.
- Panel account authority is native 3x-ui; never overwrite a running DB from an old controller snapshot. Core authority is controller state. Preserve credentials during explicit adoption and restore.
- Original files are MIT unless otherwise stated. Keep MPL-2.0 and Go notices with compatibility sources. Do not copy unlicensed forum bodies or artwork.
- Run behavior tests and relevant integration checks. Keep unavailable public/mobile tests pending; do not create a release tag until every mandatory gate passes.
