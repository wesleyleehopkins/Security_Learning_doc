/* ============================================================
   SOC Notes — app.js
   Handles sidebar toggling, content loading, navigation
   ============================================================ */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    markActiveNavLink();
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
