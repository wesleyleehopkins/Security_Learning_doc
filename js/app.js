/* ============================================================
   SOC Notes — app.js
   Handles sidebar toggling, content loading, navigation
   ============================================================ */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    markActiveNavLink();
    buildGlobalNav();
    if (window.NOTEBOOK) initNotebook();
    initNotes();
  }

  /* ── Mark active top nav link ── */
  function markActiveNavLink() {
    const page = location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-links a').forEach(a => {
      const href = (a.getAttribute('href') || '').split('/').pop();
      a.classList.toggle('active', href === page || (page === '' && href === 'index.html'));
    });
  }

  /* ── Sidebar toggle ── */
  function toggleSidebar() {
    const sb = document.getElementById('sb');
    const main = document.getElementById('main');
    if (!sb || !main) return;

    const isMobile = window.innerWidth <= 720;
    if (isMobile) {
      sb.classList.toggle('open');
    } else {
      const collapsed = sb.classList.toggle('collapsed');
      main.classList.toggle('expanded', collapsed);
      try { localStorage.setItem('sb-collapsed', collapsed); } catch (_) {}
    }
  }
  window.toggleSidebar = toggleSidebar;

  /* ── Notebook initialization ── */
  function initNotebook() {
    const nb = window.NOTEBOOK;
    document.title = nb.title + ' — SOC Notes';

    buildSidebar(nb);

    // Restore sidebar state on desktop
    if (window.innerWidth > 720) {
      try {
        if (localStorage.getItem('sb-collapsed') === 'true') {
          const sb = document.getElementById('sb');
          const main = document.getElementById('main');
          if (sb) sb.classList.add('collapsed');
          if (main) main.classList.add('expanded');
        }
      } catch (_) {}
    }

    // Load topic from hash, else first topic
    const hash = location.hash.replace('#', '');
    const first = nb.topics[0].id;
    const target = hash && nb.topics.find(t => t.id === hash) ? hash : first;
    loadTopic(target);

    window.addEventListener('hashchange', () => {
      const id = location.hash.replace('#', '');
      if (id) loadTopic(id);
    });

    // Close sidebar on mobile when clicking outside
    document.addEventListener('click', e => {
      if (window.innerWidth > 720) return;
      const sb = document.getElementById('sb');
      const btn = document.getElementById('sb-toggle');
      if (sb && sb.classList.contains('open') &&
          !sb.contains(e.target) && e.target !== btn && !btn.contains(e.target)) {
        sb.classList.remove('open');
      }
    });
  }

  /* ── Build sidebar nav from NOTEBOOK config ── */
  function buildSidebar(nb) {
    const sb = document.getElementById('sb');
    if (!sb) return;

    const header = sb.querySelector('.sidebar-header');
    if (header) {
      const titleEl = header.querySelector('.sidebar-title');
      if (titleEl) titleEl.textContent = nb.title;
    }

    const nav = document.createElement('nav');
    nav.className = 'sidebar-nav';
    nav.id = 'sb-nav';

    nb.topics.forEach(topic => {
      const item = document.createElement('div');
      item.className = 'nav-item';
      item.dataset.id = topic.id;
      item.innerHTML =
        `<span class="nav-badge">${esc(topic.badge)}</span>` +
        `<span>${esc(topic.label)}</span>`;
      item.addEventListener('click', () => {
        location.hash = topic.id;
        loadTopic(topic.id);
        // Close on mobile after selection
        if (window.innerWidth <= 720) {
          document.getElementById('sb')?.classList.remove('open');
        }
      });
      nav.appendChild(item);
    });

    // Remove existing nav if present, append new
    sb.querySelector('#sb-nav')?.remove();
    sb.appendChild(nav);
  }

  /* ── Load topic content ──
     Checks for embedded <template id="tpl-[id]"> first (works with
     file:// protocol, no server needed). Falls back to fetch() on
     GitHub Pages if a contentPath is set.                          */
  function loadTopic(id) {
    const nb = window.NOTEBOOK;
    const topic = nb.topics.find(t => t.id === id);
    if (!topic) return;

    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.id === id);
    });

    const area = document.getElementById('content-area');
    if (!area) return;

    // ── Primary: embedded <template id="tpl-[id]"> ──
    const tpl = document.getElementById('tpl-' + id);
    if (tpl) {
      area.innerHTML = tpl.innerHTML;
      window.scrollTo(0, 0);
      return;
    }

    // ── Fallback: fetch from content/ folder ──
    if (nb.contentPath) {
      area.innerHTML = `<div class="loading"><div class="spinner"></div><span>Loading…</span></div>`;
      const url = nb.contentPath + id + '.html';
      fetch(url)
        .then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
        .then(html => { area.innerHTML = html; window.scrollTo(0, 0); })
        .catch(() => {
          area.innerHTML = `<div class="topic"><h1>${esc(topic.label)}</h1><hr class="divider">
            <div class="callout note"><strong>Coming soon</strong> — content hasn't been added yet.</div></div>`;
        });
      return;
    }

    // ── Nothing found ──
    area.innerHTML = `<div class="topic"><h1>${esc(topic.label)}</h1><hr class="divider">
      <div class="callout note"><strong>Coming soon</strong> — content hasn't been added yet.</div></div>`;
  }

  /* ── HTML escape ── */
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* ══════════════════════════════════════════════════════════════
     GLOBAL NAV DRAWER — right-side slide-out with grouped topics
     ══════════════════════════════════════════════════════════════ */

  var GNAV_GROUPS = [
    { id: 'psaa', icon: '📘', label: 'PSAA Study Guide',
      items: [
        { label: 'SOC Fundamentals',             href: 'psaa.html#01-soc-fundamentals'  },
        { label: 'Phishing Analysis',            href: 'psaa.html#02-phishing'           },
        { label: 'Network Security Monitoring',  href: 'psaa.html#03-nsm'               },
        { label: 'Wireshark & tcpdump',          href: 'psaa.html#04-wireshark'          },
        { label: 'Endpoint Security Monitoring', href: 'psaa.html#05-endpoint'           },
        { label: 'Endpoint Detection & Response',href: 'psaa.html#06-edr'               },
        { label: 'Log Analysis & Management',    href: 'psaa.html#07-log-analysis'       },
        { label: 'SIEM',                         href: 'psaa.html#08-siem'              },
        { label: 'Threat Intelligence',          href: 'psaa.html#09-threat-intel'       },
        { label: 'Digital Forensics',            href: 'psaa.html#10-digital-forensics'  },
        { label: 'Incident Response',            href: 'psaa.html#11-incident-response'  },
        { label: 'Windows Investigation',        href: 'psaa.html#12-windows'           },
        { label: 'Encoding & CyberChef',         href: 'psaa.html#13-encoding'           },
        { label: 'Tools & Resources',            href: 'psaa.html#ref-tools'            },
      ]
    },
    { id: 'so', icon: '🧅', label: 'Security Onion',
      items: [
        { label: 'Overview & Tool Stack',   href: 'security-onion.html#overview'    },
        { label: 'Setup & Deployment',      href: 'security-onion.html#setup'       },
        { label: 'Alert Triage',            href: 'security-onion.html#alerts'      },
        { label: 'Dashboards',              href: 'security-onion.html#dashboards'  },
        { label: 'Hunt & KQL Queries',      href: 'security-onion.html#hunt'        },
        { label: 'Suricata IDS',            href: 'security-onion.html#suricata'    },
        { label: 'Zeek Logs',               href: 'security-onion.html#zeek'        },
        { label: 'PCAP Analysis',           href: 'security-onion.html#pcap'        },
        { label: 'Cases & Evidence',        href: 'security-onion.html#cases'       },
        { label: 'CLI & so-* Commands',     href: 'security-onion.html#cli'         },
        { label: 'Investigation Lab',       href: 'security-onion.html#lab'         },
      ]
    },
    { id: 'playbook', icon: '🔍', label: 'SOC Playbook',
      items: [
        { label: 'PICERL Framework',         href: 'investigation-flow.html#picerl-overview'      },
        { label: 'Shift Start Checklist',    href: 'investigation-flow.html#shift-start'           },
        { label: 'Alert Triage Workflow',    href: 'investigation-flow.html#alert-triage'          },
        { label: 'Process Validation',       href: 'investigation-flow.html#process-validation'    },
        { label: 'Zeek Dataset Reference',   href: 'investigation-flow.html#zeek-reference'        },
        { label: 'Sysmon Event ID Reference',href: 'investigation-flow.html#sysmon-reference'      },
        { label: 'IOC Collection Standard',  href: 'investigation-flow.html#ioc-collection'        },
        { label: 'Containment Decision',     href: 'investigation-flow.html#containment-decision'  },
        { label: 'Initial Access',           href: 'playbook-initial-access.html'                  },
        { label: 'Persistence',              href: 'playbook-persistence.html'                     },
        { label: 'Lateral Movement',         href: 'playbook-lateral.html'                         },
        { label: 'C2 / Command & Control',   href: 'playbook-c2.html'                              },
        { label: 'Exfiltration',             href: 'playbook-exfil.html'                           },
        { label: 'Credential Access',        href: 'playbook-credential.html'                      },
      ]
    },
    { id: 'splunk', icon: '🔍', label: 'Splunk',
      items: [
        { label: 'Overview',                    href: 'splunk.html'               },
        { label: 'SPL Basics',                  href: 'splunk-spl-basics.html'    },
        { label: 'Stats & Count',               href: 'splunk-stats-count.html'   },
        { label: 'Visualizations',              href: 'splunk-visualizations.html'},
        { label: 'Alerts & Enterprise Security',href: 'splunk-alerts.html'        },
        { label: 'Universal Forwarders',        href: 'splunk-forwarders.html'    },
        { label: 'Threat Hunting',              href: 'splunk-threat-hunting.html'},
        { label: 'Lab: Brute Force',            href: 'splunk-lab.html'           },
      ]
    },
    { id: 'elk', icon: '🦌', label: 'ELK Stack',
      items: [
        { label: 'Overview & Architecture', href: 'elk.html#overview'      },
        { label: 'Elasticsearch',           href: 'elk.html#elasticsearch'  },
        { label: 'Logstash Pipelines',      href: 'elk.html#logstash'       },
        { label: 'Kibana Interface',        href: 'elk.html#kibana'         },
        { label: 'Beats Agents',            href: 'elk.html#beats'          },
        { label: 'KQL & Lucene Queries',    href: 'elk.html#kql'            },
        { label: 'Index Management & ILM',  href: 'elk.html#ilm'            },
        { label: 'Elastic SIEM',            href: 'elk.html#siem'           },
        { label: 'Alerting & Watcher',      href: 'elk.html#alerting'       },
        { label: 'Tuning & Deployment',     href: 'elk.html#tuning'         },
        { label: 'Investigation Lab',       href: 'elk.html#lab'            },
      ]
    },
    { id: 'nmap', icon: '🔭', label: 'Nmap',
      items: [
        { label: 'Overview',        href: 'nmap.html'                  },
        { label: 'Scan Types',      href: 'nmap-scan-types.html'       },
        { label: 'Host Discovery',  href: 'nmap-host-discovery.html'   },
        { label: 'Service Detection',href:'nmap-service-detection.html' },
        { label: 'NSE Scripts',     href: 'nmap-nse.html'              },
        { label: 'Output Formats',  href: 'nmap-output.html'           },
        { label: 'Lab',             href: 'nmap-lab.html'              },
      ]
    },
    { id: 'wireshark', icon: '🦈', label: 'Wireshark',
      items: [
        { label: 'Overview',          href: 'wireshark.html'                    },
        { label: 'Display Filters',   href: 'wireshark-filters.html'            },
        { label: 'Capture Filters',   href: 'wireshark-capture-filters.html'    },
        { label: 'Protocol Analysis', href: 'wireshark-protocol-analysis.html'  },
        { label: 'Follow Streams',    href: 'wireshark-streams.html'            },
        { label: 'Statistics',        href: 'wireshark-statistics.html'         },
        { label: 'Lab: C2 PCAP',      href: 'wireshark-lab.html'               },
      ]
    },
    { id: 'snort', icon: '🚨', label: 'Snort',
      items: [
        { label: 'Overview',         href: 'snort.html'       },
        { label: 'Rule Syntax',      href: 'snort-rules.html' },
        { label: 'Operating Modes',  href: 'snort-modes.html' },
        { label: 'Configuration',    href: 'snort-config.html'},
        { label: 'Alert Output',     href: 'snort-alerts.html'},
        { label: 'Lab',              href: 'snort-lab.html'   },
      ]
    },
    { id: 'ossec', icon: '🛡️', label: 'OSSEC / Wazuh',
      items: [
        { label: 'Overview',                  href: 'ossec.html'                 },
        { label: 'File Integrity Monitoring', href: 'ossec-fim.html'             },
        { label: 'Rules & Decoders',          href: 'ossec-rules.html'           },
        { label: 'Active Response',           href: 'ossec-active-response.html' },
        { label: 'Manager Setup',             href: 'ossec-manager.html'         },
        { label: 'Lab',                       href: 'ossec-lab.html'             },
      ]
    },
    { id: 'openvas',      icon: '🔬', label: 'OpenVAS',        items: [{ label: 'OpenVAS Reference',      href: 'openvas.html'      }] },
    { id: 'kali',         icon: '🐉', label: 'Kali Linux',     items: [{ label: 'Kali Linux Reference',   href: 'kali.html'         }] },
    { id: 'metasploit',   icon: '💀', label: 'Metasploit',     items: [{ label: 'Metasploit Reference',   href: 'metasploit.html'   }] },
    { id: 'yara',         icon: '🎯', label: 'YARA',           items: [{ label: 'YARA Reference',         href: 'yara.html'         }] },
    { id: 'zeek',         icon: '🌊', label: 'Zeek',           items: [{ label: 'Zeek Reference',         href: 'zeek.html'         }] },
    { id: 'clamav',       icon: '🦠', label: 'ClamAV',         items: [{ label: 'ClamAV Reference',       href: 'clamav.html'       }] },
    { id: 'misp',         icon: '🔗', label: 'MISP',           items: [{ label: 'MISP Reference',         href: 'misp.html'         }] },
    { id: 'cuckoo',       icon: '🥚', label: 'Cuckoo Sandbox', items: [{ label: 'Cuckoo Reference',       href: 'cuckoo.html'       }] },
    { id: 'velociraptor', icon: '🦖', label: 'Velociraptor',   items: [{ label: 'Velociraptor Reference', href: 'velociraptor.html' }] },
    { id: 'autopsy',      icon: '🩺', label: 'Autopsy',        items: [{ label: 'Autopsy Reference',      href: 'autopsy.html'      }] },
    { id: 'anyrun',       icon: '🧪', label: 'ANY.RUN',        items: [{ label: 'ANY.RUN Reference',      href: 'anyrun.html'       }] },
    { id: 'logsources',   icon: '📋', label: 'Log Sources',    items: [{ label: 'SOC Log Cheat Sheet',    href: 'log-sources.html'  }] },
    { id: 'redteam',      icon: '⚔️', label: 'Red Team Lab',  items: [{ label: 'Red Team Correlation Lab',href:'redteam-correlation.html'}] },
  ];

  function buildGlobalNav() {
    var navbar = document.querySelector('.navbar');
    if (!navbar) return;

    // Current page filename for active detection
    var curPage = location.pathname.split('/').pop() || 'index.html';
    var curHash = location.hash.replace('#', '');

    // ── Inject the trigger button ──
    var btn = document.createElement('button');
    btn.className = 'gnav-btn';
    btn.id = 'gnav-btn';
    btn.setAttribute('aria-label', 'Open navigation');
    btn.setAttribute('aria-expanded', 'false');
    btn.innerHTML =
      '<svg width="14" height="11" viewBox="0 0 14 11" fill="currentColor">' +
        '<rect width="14" height="2" rx="1"/>' +
        '<rect y="4.5" width="14" height="2" rx="1"/>' +
        '<rect y="9" width="14" height="2" rx="1"/>' +
      '</svg> Navigate';
    navbar.appendChild(btn);

    // ── Overlay ──
    var overlay = document.createElement('div');
    overlay.className = 'gnav-overlay';
    overlay.id = 'gnav-overlay';
    document.body.appendChild(overlay);

    // ── Drawer ──
    var drawer = document.createElement('div');
    drawer.className = 'gnav-drawer';
    drawer.id = 'gnav-drawer';
    drawer.setAttribute('aria-hidden', 'true');

    // Header
    var header = document.createElement('div');
    header.className = 'gnav-header';
    var title = document.createElement('span');
    title.className = 'gnav-title';
    title.textContent = 'Navigate';
    var closeBtn = document.createElement('button');
    closeBtn.className = 'gnav-close';
    closeBtn.setAttribute('aria-label', 'Close navigation');
    closeBtn.textContent = '✕';
    header.appendChild(title);
    header.appendChild(closeBtn);
    drawer.appendChild(header);

    // Body
    var body = document.createElement('div');
    body.className = 'gnav-body';

    // Home link
    var homeLink = document.createElement('a');
    homeLink.className = 'gnav-home' + (curPage === 'index.html' ? ' active' : '');
    homeLink.href = 'index.html';
    homeLink.textContent = '⬡  Home';
    body.appendChild(homeLink);

    // Build groups
    GNAV_GROUPS.forEach(function(grp) {
      var isSingle = grp.items.length === 1;

      // Determine if this group contains the active page
      var groupActive = grp.items.some(function(item) {
        var hrefPage = item.href.split('#')[0].split('/').pop();
        return hrefPage === curPage;
      });

      var groupEl = document.createElement('div');
      groupEl.className = 'gnav-group';

      if (isSingle) {
        // Render as a direct anchor, no chevron
        var hdr = document.createElement('a');
        hdr.className = 'gnav-group-hdr' + (groupActive ? ' active-group' : '');
        hdr.href = grp.items[0].href;
        hdr.innerHTML =
          '<span class="gnav-group-icon">' + grp.icon + '</span>' +
          '<span class="gnav-group-label">' + esc(grp.label) + '</span>';
        groupEl.appendChild(hdr);
      } else {
        // Collapsible group
        var hdr = document.createElement('button');
        hdr.className = 'gnav-group-hdr' + (groupActive ? ' active-group' : '');
        var expanded = groupActive; // auto-expand if current page is inside
        hdr.setAttribute('aria-expanded', String(expanded));
        hdr.innerHTML =
          '<span class="gnav-group-icon">' + grp.icon + '</span>' +
          '<span class="gnav-group-label">' + esc(grp.label) + '</span>' +
          '<span class="gnav-chevron">›</span>';

        var itemList = document.createElement('div');
        itemList.className = 'gnav-group-items';
        if (!expanded) itemList.hidden = true;

        grp.items.forEach(function(item) {
          var itemPage = item.href.split('#')[0].split('/').pop();
          var itemHash = item.href.split('#')[1] || '';
          var isActive = itemPage === curPage && (!itemHash || itemHash === curHash);

          var a = document.createElement('a');
          a.className = 'gnav-item' + (isActive ? ' active' : '');
          a.href = item.href;
          a.textContent = item.label;
          itemList.appendChild(a);
        });

        hdr.addEventListener('click', function() {
          var nowExpanded = hdr.getAttribute('aria-expanded') === 'true';
          hdr.setAttribute('aria-expanded', String(!nowExpanded));
          itemList.hidden = nowExpanded;
        });

        groupEl.appendChild(hdr);
        groupEl.appendChild(itemList);
      }

      body.appendChild(groupEl);
    });

    drawer.appendChild(body);
    document.body.appendChild(drawer);

    // ── Open / close logic ──
    function openDrawer() {
      drawer.classList.add('open');
      overlay.classList.add('open');
      btn.setAttribute('aria-expanded', 'true');
      drawer.setAttribute('aria-hidden', 'false');
    }
    function closeDrawer() {
      drawer.classList.remove('open');
      overlay.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
      drawer.setAttribute('aria-hidden', 'true');
    }

    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      drawer.classList.contains('open') ? closeDrawer() : openDrawer();
    });
    closeBtn.addEventListener('click', closeDrawer);
    overlay.addEventListener('click', closeDrawer);

    // Close on Escape key
    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape' && drawer.classList.contains('open')) closeDrawer();
    });
  }

  /* ── Per-page notes with localStorage ── */
  function initNotes() {
    // Derive a safe storage key from the current filename
    var raw = location.pathname.split('/').pop() || 'index.html';
    var pageKey = raw.replace(/\.html?$/i, '').replace(/[^a-zA-Z0-9_-]/g, '') || 'index';
    var storageKey = 'soc-notes-' + pageKey;

    // Build FAB button
    var fab = document.createElement('button');
    fab.className = 'notes-fab';
    fab.setAttribute('aria-label', 'Toggle notes');
    fab.title = 'Page notes';
    fab.textContent = '\u270E'; // ✎ pencil
    document.body.appendChild(fab);

    // Build panel
    var panel = document.createElement('div');
    panel.className = 'notes-panel';

    var header = document.createElement('div');
    header.className = 'notes-panel-header';
    var titleSpan = document.createElement('strong');
    titleSpan.textContent = 'Notes';
    var countSpan = document.createElement('span');
    countSpan.className = 'notes-count';
    header.appendChild(titleSpan);
    header.appendChild(countSpan);

    var textarea = document.createElement('textarea');
    textarea.placeholder = 'Type your notes here\u2026';
    textarea.setAttribute('spellcheck', 'true');

    var toolbar = document.createElement('div');
    toolbar.className = 'notes-toolbar';

    var btnCopy = document.createElement('button');
    btnCopy.textContent = 'Copy';
    var btnDownload = document.createElement('button');
    btnDownload.textContent = 'Download';
    var btnClear = document.createElement('button');
    btnClear.textContent = 'Clear';

    toolbar.appendChild(btnCopy);
    toolbar.appendChild(btnDownload);
    toolbar.appendChild(btnClear);

    panel.appendChild(header);
    panel.appendChild(textarea);
    panel.appendChild(toolbar);
    document.body.appendChild(panel);

    // ── Helpers ──
    function updateCount() {
      var len = textarea.value.length;
      countSpan.textContent = len > 0 ? len + ' chars' : '';
    }

    function updateFabIndicator() {
      var saved = '';
      try { saved = localStorage.getItem(storageKey) || ''; } catch (_) {}
      fab.classList.toggle('has-notes', saved.length > 0);
    }

    // ── Load saved notes ──
    try {
      var saved = localStorage.getItem(storageKey);
      if (saved) textarea.value = saved;
    } catch (_) {}
    updateCount();
    updateFabIndicator();

    // ── Debounced save ──
    var saveTimer = null;
    textarea.addEventListener('input', function () {
      updateCount();
      clearTimeout(saveTimer);
      saveTimer = setTimeout(function () {
        try {
          if (textarea.value) {
            localStorage.setItem(storageKey, textarea.value);
          } else {
            localStorage.removeItem(storageKey);
          }
        } catch (_) {}
        updateFabIndicator();
      }, 300);
    });

    // ── Toggle panel ──
    fab.addEventListener('click', function (e) {
      e.stopPropagation();
      panel.classList.toggle('open');
      if (panel.classList.contains('open')) textarea.focus();
    });

    // Close panel when clicking outside
    document.addEventListener('click', function (e) {
      if (panel.classList.contains('open') &&
          !panel.contains(e.target) && e.target !== fab) {
        panel.classList.remove('open');
      }
    });

    // ── Copy ──
    btnCopy.addEventListener('click', function () {
      if (!textarea.value) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textarea.value).then(function () {
          btnCopy.textContent = 'Copied!';
          setTimeout(function () { btnCopy.textContent = 'Copy'; }, 1500);
        });
      } else {
        // Fallback for file:// protocol where clipboard API may not work
        textarea.select();
        document.execCommand('copy');
        btnCopy.textContent = 'Copied!';
        setTimeout(function () { btnCopy.textContent = 'Copy'; }, 1500);
      }
    });

    // ── Download ──
    btnDownload.addEventListener('click', function () {
      if (!textarea.value) return;
      var safeName = pageKey.replace(/[^a-zA-Z0-9_-]/g, '') + '-notes.txt';
      var blob = new Blob([textarea.value], { type: 'text/plain' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = safeName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });

    // ── Clear ──
    btnClear.addEventListener('click', function () {
      if (!textarea.value) return;
      if (!confirm('Clear all notes for this page?')) return;
      textarea.value = '';
      try { localStorage.removeItem(storageKey); } catch (_) {}
      updateCount();
      updateFabIndicator();
    });
  }
})();
