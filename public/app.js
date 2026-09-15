// ── Shared API helpers ─────────────────────────────────────────────────────────
export const api = {
  async get(url) {
    const res = await fetch(url);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
  async post(url, body) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
  async patch(url, body) {
    const res = await fetch(url, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
  async delete(url) {
    const res = await fetch(url, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
};

// ── Toast ──────────────────────────────────────────────────────────────────────
export function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Format helpers ─────────────────────────────────────────────────────────────
export function formatDate(iso) {
  if (!iso) return '';
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatViews(n) {
  if (n == null) return '0';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return String(n);
}

export function formatBytes(b) {
  if (!b) return '0 B';
  if (b < 1024) return b + ' B';
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + ' MB';
  return (b / 1024 ** 3).toFixed(2) + ' GB';
}

export function roleLabel(role) {
  return ({
    owner: 'Owner',
    admin: 'Admin',
    moderator: 'Moderator',
    developer: 'Developer',
    beta_tester: 'Beta Tester',
    bug_hunter: 'Bug Hunter',
    contributor: 'Contributor',
    booster: 'Booster',
    og_user: 'OG User',
    user: 'User',
  })[role] || 'User';
}

function escHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── Navbar ─────────────────────────────────────────────────────────────────────
export async function initNav() {
  const nav = document.getElementById('nav-actions');
  if (!nav) return;
  try {
    const { user } = await api.get('/api/auth/me');
    if (user) {
      if (!user.hasEmail && !document.getElementById('legacy-email-warning')) {
        document.body.insertAdjacentHTML('afterbegin', `
          <div class="account-warning" id="legacy-email-warning" role="status">
            <span>Your account does not have an email address yet. Add one to improve account recovery and security.</span>
            <a href="/settings.html">Add email</a>
          </div>
        `);
      }
      nav.innerHTML = `
        <a href="/my-uploads.html" class="btn btn-ghost btn-sm">My Uploads</a>
        <a href="/channel.html?handle=${encodeURIComponent(user.username)}" class="btn btn-ghost btn-sm">Channel</a>
        <a href="/bug-report.html" class="btn btn-ghost btn-sm">Report bug</a>
        ${(user.banned || user.restricted) ? '<a href="/appeal.html" class="btn btn-ghost btn-sm">Appeal</a>' : ''}
        ${!user.hasEmail ? '<a href="/settings.html" class="btn btn-ghost btn-sm">Settings</a>' : ''}
        ${user.role === 'owner' ? `<a href="/settings.html" class="btn btn-ghost btn-sm">${user.adminMode ? 'Owner mode' : 'Settings'}</a>` : ''}
        ${user.canModerate ? '<a href="/admin.html" class="btn btn-primary btn-sm">Moderate</a>' : ''}
        ${user.canViewDeveloperTools ? '<a href="/developer.html" class="btn btn-ghost btn-sm">Developer</a>' : ''}
        <a href="/upload.html" class="btn btn-primary btn-sm">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Upload
        </a>
        <button class="btn btn-ghost btn-sm" id="logout-btn">${escHtml(user.username)}</button>
      `;
      document.getElementById('logout-btn')?.addEventListener('click', async () => {
        await api.post('/api/auth/logout', {});
        window.location.href = '/';
      });
    } else {
      nav.innerHTML = `
        <a href="/login.html" class="btn btn-ghost btn-sm">Sign in</a>
        <a href="/register.html" class="btn btn-primary btn-sm">Create account</a>
      `;
    }
  } catch {
    nav.innerHTML = `
      <a href="/login.html" class="btn btn-ghost btn-sm">Sign in</a>
      <a href="/register.html" class="btn btn-primary btn-sm">Create account</a>
    `;
  }
}

// ── Home page: video grid + pagination + search ────────────────────────────────
let currentPage = 1;
let currentQuery = '';
let currentSort = 'recent';
let currentCategory = '';

export async function loadVideos(page = 1, q = currentQuery, sort = currentSort, category = currentCategory) {
  currentPage = page;
  currentQuery = q;
  currentSort = sort;
  currentCategory = category;

  const wrap = document.getElementById('video-grid-wrap');
  const paginationEl = document.getElementById('pagination');
  const sectionTitle = document.getElementById('section-title');
  if (!wrap) return;

  wrap.innerHTML = '<div class="loader"><div class="spinner"></div></div>';

  try {
    const params = new URLSearchParams({ page, limit: 20, sort });
    if (q) params.set('q', q);
    if (category) params.set('category', category);
    const data = await api.get(`/api/videos?${params}`);
    const { videos, pagination } = data;

    if (sectionTitle) {
      sectionTitle.textContent = q ? `Results for "${q}"` : sort === 'trending' ? 'Trending Videos' : 'Latest Videos';
    }

    if (!videos.length) {
      wrap.innerHTML = `
        <div class="empty-state">
          <svg width="56" height="56" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><rect x="2" y="2" width="20" height="20" rx="3"/><polygon points="10 8 16 12 10 16 10 8"/></svg>
          <h3>${q ? 'No results found' : 'No videos yet'}</h3>
          <p>${q ? 'Try a different search term.' : 'Be the first to upload a video!'}</p>
        </div>`;
      if (paginationEl) paginationEl.innerHTML = '';
      return;
    }

    wrap.innerHTML = `<div class="video-grid">${videos.map(videoCard).join('')}</div>`;

    // Pagination
    if (paginationEl) {
      paginationEl.innerHTML = buildPagination(pagination);
    }
  } catch (err) {
    wrap.innerHTML = `<p style="color:var(--text-muted);padding:2rem">Failed to load videos: ${escHtml(err.message)}</p>`;
  }
}

function videoCard(v) {
  return `
    <article class="video-card" onclick="location.href='/watch.html?id=${v.id}'" tabindex="0" role="button"
             onkeydown="if(event.key==='Enter')location.href='/watch.html?id=${v.id}'">
      <div class="video-thumb">
        <img src="/api/videos/${v.id}/thumbnail" alt="${escHtml(v.title)}" loading="lazy"/>
        <div class="play-overlay">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
        </div>
      </div>
      <div class="video-info">
        <p class="video-title">${escHtml(v.title)}</p>
        <div class="video-meta">
           <span>${v.channel_handle ? `<a href="/channel.html?handle=${encodeURIComponent(v.channel_handle)}" onclick="event.stopPropagation()">${escHtml(v.channel_name || v.uploader)}</a>` : escHtml(v.uploader)}</span>
           <span>${formatViews(v.view_count)} views</span>
           <span>${formatViews(v.like_count)} likes</span>
           ${v.category ? `<span class="video-category">${escHtml(v.category)}</span>` : ''}
          <span>${formatDate(v.created_at)}</span>
        </div>
      </div>
    </article>`;
}

function buildPagination({ page, pages }) {
  if (pages <= 1) return '';
  let html = '';
  const prev = page - 1;
  const next = page + 1;

  html += `<button class="page-btn" ${page === 1 ? 'disabled' : ''} onclick="window.__gotoPage(${prev})">← Prev</button>`;
  const range = getPageRange(page, pages);
  for (const p of range) {
    if (p === '…') {
      html += `<span class="page-btn" style="cursor:default">…</span>`;
    } else {
      html += `<button class="page-btn ${p === page ? 'active' : ''}" onclick="window.__gotoPage(${p})">${p}</button>`;
    }
  }
  html += `<button class="page-btn" ${page === pages ? 'disabled' : ''} onclick="window.__gotoPage(${next})">Next →</button>`;
  return html;
}

function getPageRange(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  if (current <= 4) return [1, 2, 3, 4, 5, '…', total];
  if (current >= total - 3) return [1, '…', total - 4, total - 3, total - 2, total - 1, total];
  return [1, '…', current - 1, current, current + 1, '…', total];
}

window.__gotoPage = (p) => loadVideos(p, currentQuery, currentSort, currentCategory);

// ── Search wiring (only on index page) ────────────────────────────────────────
if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('search-input');
    const btn = document.getElementById('search-btn');
    if (!input) return;

    let debounce;
    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        loadVideos(1, input.value.trim(), currentSort, currentCategory);
      }, 400);
    });
    btn?.addEventListener('click', () => loadVideos(1, input.value.trim(), currentSort, currentCategory));
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') loadVideos(1, input.value.trim(), currentSort, currentCategory);
    });
    document.getElementById('sort-select')?.addEventListener('change', (event) => {
      loadVideos(1, input.value.trim(), event.target.value, document.getElementById('category-select')?.value || '');
    });
    document.getElementById('category-select')?.addEventListener('change', (event) => {
      loadVideos(1, input.value.trim(), document.getElementById('sort-select')?.value || 'recent', event.target.value);
    });
  });
}
