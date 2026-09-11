# Bifrost Temp Install Helper ori

**Disposable** PTE for [bc-origo-bifrost-core#38](https://github.com/OrigoSoftwareSolutions/bc-origo-bifrost-core/issues/38).

Grants / revokes exactly two `Access Control` rows on a named BC user (typically the `ce-bifrost` service principal) so Foundation install-time take-over can read legacy Cloud Events Field Access (`10075489`) **without SUPER**.

| | |
|---|---|
| App | Bifrost Temp Install Helper ori `b4142ecf-ed59-4001-8967-b2d7454b923c` |
| Publisher / version | Origo / 28.0.0.0 (platform/application 28.0.0.0, runtime 17.0) |
| Object IDs | **50100–50104** (tests **50190–50199**) |
| Dependencies | Origo Cloud Events Core only (`a629b897-…`) — **no Bifrost Foundation** |
| Message type | `Temp.InstallHelper.Access` |

Uninstall after CE-BIFROST Foundation publish succeeds and `revoke` has been run.

## Actions (`data.action`)

| action | Behaviour |
|---|---|
| `report` | Access Control rows for the user + `legacyReadProbe` on table `10075489` |
| `grant` | Insert if missing: `CE Full Access ori` (Tenant / CE Core App ID) + `SECURITY` (System / empty App ID); company blank |
| `revoke` | Delete exactly those two rows (idempotent) |

`data.userName` = BC `User."User Name"`; empty → current invoker.

## Never

- No SUPER
- No Bifrost Foundation dependency
- No Field Access migrate / TakeOver.Legacy.*
