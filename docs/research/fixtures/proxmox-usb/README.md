# Proxmox USB mapping recordings (FM-S11, #563)

Recorded 2026-10-30 against the integration host (`pve-9.2.2/`, PVE 9.2.2) and the
nested fixture (`pve-8.4.0/`, PVE 8.4.0) for the analysis in
[`../../proxmox-usb.md`](../../proxmox-usb.md). They are candidate contract
fixtures for the M11 provider tests (FM-1110, FM-1122).

Each file is one request and its response:

```json
{
  "pve_version": "9.2.2",
  "who": "root | probe",
  "recorded_with": "...",
  "request": { "method": "PUT", "path": "/nodes/pve/qemu/9563/config", "params": { "usb0": "mapping=..." } },
  "http_status": 200,
  "response": null
}
```

- `who: probe` records are real HTTP: `curl` with a temporary privilege-separated API
  token; `http_status` and `response` (`data`, or `{message, errors}` on failure) are
  what the API returned. Use these for provider error mapping.
- `who: root` records come from `pvesh` on the node. `http_status` and `response` are
  reconstructed from the CLI: a successful config write is `null` (the `pvesh_log`
  member keeps the CLI's progress line), an asynchronous call is the UPID string (the
  `task_log` member keeps the task output the CLI printed), and a `400 Parameter
  verification failed` is rebuilt as `{message, errors}`.
- `tasks-qmstart.json` holds the task log and status of each guest start the spike
  made; a refused start is a task that ends `TASK ERROR: ...`, not an HTTP error.
- `n-start-*.json` hold only the UPID of a start that later failed; the outcome is in
  `tasks-qmstart.json`.

Prefixes: `q*` shapes, `r*` re-enumeration, `h*`/`d*`/`p*` hotplug and pending, `a*`/`b*`
failed hotplug, `e*` second guest, `i*` ambiguous and multi-entry mappings, `k*` digest,
`n*` start with unusable mappings, `t*` snapshot/clone/template, `m*` migration preflight,
`pr*`/`pw*` privileges (9.2.2), `qr*`/`qw*` privileges and `*8-` the 8.4 equivalents.

Sanitization: IP addresses, MAC addresses, UUIDs (smbios, vmgenid) and the node's TLS
fingerprint are replaced with documentation values. No token, ticket or password was
ever written; the API returns no device serial. Node names (`pve`, `pve8`) and the
test mapping names are kept.
