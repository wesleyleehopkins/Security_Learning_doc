# SOC Notes — Project Instructions

## Architecture: Server-Free Static Site

This project is intentionally designed to run **without any web server**. All HTML files open directly in the browser via `file://` protocol by double-clicking them.

**Do NOT start a dev server. Do NOT call `preview_start`. The project does not require one.**

### Why no server?
- All content is embedded in `<template id="tpl-[id]">` elements inside each HTML file
- `app.js` reads `template.innerHTML` directly — no fetch() calls needed
- Works offline and locally without broadcasting a server

### File Structure
```
index.html              — Landing page with notebook cards
psaa.html               — PSAA Study Guide notebook (14 topics, all embedded)
security-onion.html     — Security Onion notebook (8 topics, all embedded)
splunk.html             — Splunk overview notebook
splunk-spl-basics.html  — SPL search language reference
splunk-stats-count.html — stats, eval, dedup, timechart
splunk-visualizations.html — Dashboard and chart reference
splunk-alerts.html      — Alerts and Enterprise Security
splunk-forwarders.html  — Universal Forwarder configuration
splunk-threat-hunting.html — MITRE ATT&CK hunting queries
splunk-lab.html         — Brute force investigation lab walkthrough
log-sources.html        — Iframes soc-log-cheatsheet.html
css/style.css           — Dark theme stylesheet (do not modify structure)
js/app.js               — Sidebar toggle + template-based content loading
```

### Adding Content
- Each notebook page uses `window.NOTEBOOK` config to define sidebar topics
- Content lives in `<template id="tpl-[id]">` elements — invisible until clicked
- Use `<article class="topic">` inside each template
- Tables need `.table-wrap` wrapper div
- Code blocks use `<pre><code>` with `<span class="cm">` for comments

### Verification After Edits
Open the HTML file directly in your browser to verify. No server needed.
