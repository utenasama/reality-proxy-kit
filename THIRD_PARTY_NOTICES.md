# Third-party notices and provenance

Original independently authored kit code, skill instructions, documentation and neutral website template are MIT, except where a file/directory states another license. This does not relicense bundled patches, upstream code or dependencies.

| Component | Source / pin | License / distribution |
| --- | --- | --- |
| Xray-core | XTLS/Xray-core `1b1647cd9ddf0abc34b981d4611fc03bcac1ca74` | MPL-2.0; modified corresponding source accompanies any distributed core |
| REALITY | XTLS/REALITY `83f621788ca88b83179810b12baa7ae518aacb83` | MPL-2.0 and preserved Go/BSD notices; compatibility patch stays MPL-2.0 |
| sing-box | SagerNet/sing-box v1.14.2 | GPL-3.0-or-later and upstream project-name/association statement; fetched from pinned upstream artifact, not repackaged here |
| 3x-ui | MHSanaei/3x-ui v3.11.0 | GPLv3; fetched from pinned upstream artifact; no bundled upstream Xray is installed |
| Go | 1.27.3 | Go BSD license; compiler toolchain is not part of the source repository |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause and upstream dependency notices |
| PyYAML | 6.0.3 | MIT |
| qrcode | 8.2 | BSD |
| cffi / pycparser | Installed as cryptography dependencies | MIT / BSD; versions recorded in test environment |
| Ubuntu, Nginx, Certbot, nftables, Python | Ubuntu 24.04 packages | Installed through OS package manager; retain distribution licensing and security updates |

Full core/REALITY/Go and optional binary component license texts are under `licenses/`. Vendored Go module notices and the actual module inventory are included in the modified core source archive. Wheel/system package notices remain with their distributions. Do not redistribute optional third-party binaries under the kit MIT license.

Conceptual inspiration: [Linux.do chain tutorial](https://linux.do/t/topic/2086346). No forum body, screenshots or artwork are redistributed. The earlier single-VPS source excerpt is unavailable; the new guide is original and based on verifiable upstream mechanisms. This repository carries no production host inventory, customer data, original project history, artwork, portal or full routing-rule package.

Upstream references: [Xray](https://github.com/XTLS/Xray-core), [REALITY](https://github.com/XTLS/REALITY), [sing-box](https://github.com/SagerNet/sing-box), [3x-ui](https://github.com/MHSanaei/3x-ui), [Go license](https://go.dev/LICENSE).
