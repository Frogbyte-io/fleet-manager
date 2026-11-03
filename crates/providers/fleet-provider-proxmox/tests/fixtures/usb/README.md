# USB read fixtures (FM-1110)

Real recordings from the FM-S11 spike (#563), copied unchanged from
[`docs/research/fixtures/proxmox-usb/`](../../../../../../docs/research/fixtures/proxmox-usb/README.md)
under the same file names, for `tests/usb_reads.rs`. `pve9/` was recorded on
PVE 9.2.2 and `pve8/` on PVE 8.4.0. Each file is one request and its
response; `who: probe` records are the real HTTP status and body of a
privilege-separated token, `who: root` records come from `pvesh`.

They are sanitized as the spike's README describes: no token, ticket,
password, device serial (the API returns none), IP address or MAC address;
the node names (`pve`, `pve8`) and the test mapping names are kept. A test
in `usb_reads.rs` scans every file for serials, address-shaped runs and
credential words.

| Fixture | Request | What it pins |
|---|---|---|
| `v0-version`, `v8-version` | `GET /version` | The version every read starts with |
| `q1-mapping-list`, `v8-mapping-list` | `GET /cluster/mapping/usb` | Path and id-only entries, an operator description, PVE's unordered list |
| `q1-mapping-list-check-node`, `v8-mapping-list-check-node` | `?check-node=<node>` | `errors[]` empty, `usb device ... not found`, `'id' does not match` |
| `q5-mapping-nonode-check` | `?check-node=pve` | `No mapping for node pve.` (a warning) |
| `r1-mapping-check-unplugged` | `?check-node=pve` | A disconnected device |
| `i4-two-entries-check` | `?check-node=pve` | A mapping with two entries for one node, an id-only entry, a path that does not exist: PVE flags none of the first two |
| `q1-mapping-get-path`, `v8-mapping-get` | `GET /cluster/mapping/usb/<id>` | The per-mapping answer has no `id` |
| `q1-hardware-usb`, `v8-hardware-usb` | `GET /nodes/{node}/hardware/usb` | Root hubs carry no `usbpath`; no serial |
| `pr0-list-mappings`, `qr0-list-mappings`, `v8-mapping-list-empty` | `GET /cluster/mapping/usb` | Without `Mapping.Audit` the list is an empty `200` |
| `pr0-get-mapping`, `qr0-get-mapping` | `GET /cluster/mapping/usb/<id>` | The same token gets a 403 here: the probe |
| `pr0-hardware-usb`, `qr0-hardware-usb` | `GET /nodes/{node}/hardware/usb` | 403 `Permission check failed (/, Sys.Modify)` |

No PVE that predates resource mappings was recorded, so the
endpoint-absent answers (501 `Method '...' not implemented`, and 404) are
synthetic and inline in the test. Malformed and oversized answers are inline
too.
