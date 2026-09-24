// Fleet Console v2 mockups — injects the shared sidebar/topbar and the
// theme/corner toggles so each option file only carries its page body.
const I = {
  overview: '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>',
  fleet: '<rect x="3" y="4" width="18" height="6"/><rect x="3" y="14" width="18" height="6"/><path d="M7 7h.01M7 17h.01"/>',
  proxmox: '<path d="M4 6l8-3 8 3v6c0 5-4 8-8 9-4-1-8-4-8-9z"/>',
  tailnet: '<circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M8 6h8M7 8l4 8M17 8l-4 8"/>',
  containers: '<path d="M3 8l9-5 9 5v8l-9 5-9-5z"/><path d="M3 8l9 5 9-5M12 13v8"/>',
  projects: '<path d="M3 6h7l2 2h9v11H3z"/>',
  lab: '<path d="M9 3h6M10 3v6l-6 11h16L14 9V3"/>',
  skills: '<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>',
  images: '<rect x="3" y="3" width="18" height="18"/><path d="M3 15l5-5 5 5 3-3 5 5"/>',
  ops: '<path d="M4 12h4l3-8 3 16 3-8h3"/>',
  audit: '<path d="M6 3h9l4 4v14H6z"/><path d="M9 11h7M9 15h7"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M5 19l2-2M17 7l2-2"/>',
}
const NAV = [
  [null, [['overview', 'Overview', 'overview-a-cards.html']]],
  ['Infrastructure', [
    ['fleet', 'Fleet', 'overview-a-cards.html', '14'],
    ['proxmox', 'Proxmox', '#', '2'],
    ['tailnet', 'Tailnet', '#', '3 new'],
    ['containers', 'Containers', '#', 'soon'],
  ]],
  ['Work', [
    ['projects', 'Projects', '#', '6'],
    ['skills', 'Skills', 'skills.html', '1 drift'],
    ['lab', 'Lab', 'lab-a-dashboard.html', '3'],
    ['images', 'Images', 'lab-b-pipeline.html'],
  ]],
  ['Control', [
    ['ops', 'Operations', '#', 'hot:2'],
    ['audit', 'Audit log', '#'],
    ['settings', 'Settings', 'settings.html'],
  ]],
]
function svg(k) { return `<svg viewBox="0 0 24 24">${I[k]}</svg>` }
function sidebar(active) {
  let h = `<aside class="side"><div class="brand"><div class="mark">F</div><div><b>Fleet Console</b><small>CONTROLLER · HOMELAB</small></div></div><nav class="nav">`
  for (const [g, items] of NAV) {
    if (g) h += `<div class="grp kick">${g}</div>`
    for (const [k, label, href, c] of items) {
      let cnt = ''
      if (c === 'soon') cnt = '<span class="soon">M5</span>'
      else if (c?.startsWith('hot:')) cnt = `<span class="cnt hot">${c.slice(4)}</span>`
      else if (c) cnt = `<span class="cnt">${c}</span>`
      h += `<a href="${href}" class="${k === active ? 'on' : ''}">${svg(k)}<span class="t">${label}</span>${cnt}</a>`
    }
  }
  h += `</nav><div class="foot"><div><span class="dot"></span>CONTROLLER READY</div><div class="row"><span>v0.7.0 · TRUSTED LAN</span><span>⚠</span></div></div></aside>`
  return h
}
function topbar(crumb) {
  return `<header class="top"><div class="crumb">${crumb}</div><div class="search">⌕ Search machines, VMs, leases, actions…<kbd>⌘K</kbd></div><button class="btn pri">+ Add</button></header>`
}
document.addEventListener('DOMContentLoaded', () => {
  const b = document.body
  const main = document.querySelector('.main')
  b.insertAdjacentHTML('afterbegin', sidebar(b.dataset.active))
  main.insertAdjacentHTML('afterbegin', topbar(b.dataset.crumb || ''))
  const root = document.documentElement
  const q = new URLSearchParams(location.search)
  root.dataset.theme = q.get('theme') || localStorage.getItem('fleet-console-theme') || 'dark'
  root.dataset.corners = q.get('corners') || localStorage.getItem('fleet-mock-corners') || 'sharp'
  b.insertAdjacentHTML('beforeend', `<div class="mock"><span style="align-self:center;color:var(--faint)">MOCKUP</span><button id="mt">theme</button><button id="mc">corners</button><a class="btn sm" href="index.html">all options</a></div>`)
  document.getElementById('mt').onclick = () => { root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark'; localStorage.setItem('fleet-console-theme', root.dataset.theme) }
  document.getElementById('mc').onclick = () => { root.dataset.corners = root.dataset.corners === 'soft' ? 'sharp' : 'soft'; localStorage.setItem('fleet-mock-corners', root.dataset.corners) }
})
