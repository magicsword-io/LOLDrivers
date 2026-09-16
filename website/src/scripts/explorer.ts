import type { DriverSummary } from '../lib/drivers';

const input = document.querySelector<HTMLInputElement>('#search')!;
const hvci = document.querySelector<HTMLSelectElement>('#hvci')!;
const sort = document.querySelector<HTMLSelectElement>('#sort')!;
const previous = document.querySelector<HTMLButtonElement>('#previous')!;
const next = document.querySelector<HTMLButtonElement>('#next')!;
const rows = document.getElementById('rows')!;
const count = document.getElementById('result-count')!;
const error = document.getElementById('search-error')!;
let drivers: DriverSummary[] | undefined;
let loading: Promise<void> | undefined;
let category = 'all';
let page = 0;
const pageSize = 12;
const escapeHTML = (value: unknown) =>
  String(value).replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ]!,
  );

function readState() {
  const params = new URLSearchParams(location.search);
  input.value = params.get('q') || '';
  category = ['all', 'malicious', 'vulnerable driver'].includes(
    params.get('category') || '',
  )
    ? params.get('category')!
    : 'all';
  hvci.value = ['yes', 'no', 'unknown'].includes(params.get('hvci') || '')
    ? params.get('hvci')!
    : 'all';
  sort.value = ['name', 'samples'].includes(params.get('sort') || '')
    ? params.get('sort')!
    : 'recent';
  page = Math.max(0, Number.parseInt(params.get('page') || '1', 10) - 1) || 0;
}
function writeState() {
  const url = new URL(location.href);
  for (const [key, value, fallback] of [
    ['q', input.value.trim(), ''],
    ['category', category, 'all'],
    ['hvci', hvci.value, 'all'],
    ['sort', sort.value, 'recent'],
    ['page', String(page + 1), '1'],
  ]) {
    if (value === fallback) url.searchParams.delete(key);
    else url.searchParams.set(key, value);
  }
  history.replaceState(null, '', url);
}
function render() {
  if (!drivers) return;
  const query = input.value.trim().toLowerCase();
  const hash = /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(query);
  const results = drivers.filter(
    (d) =>
      (category === 'all' || d.category === category) &&
      (!query ||
        (hash
          ? d.search.split(/\s+/).includes(query)
          : d.search.includes(query))) &&
      (hvci.value === 'all' || d[hvci.value as 'yes' | 'no' | 'unknown'] > 0),
  );
  results.sort((a, b) =>
    sort.value === 'name'
      ? a.name.localeCompare(b.name)
      : sort.value === 'samples'
        ? b.samples - a.samples || a.name.localeCompare(b.name)
        : b.created.localeCompare(a.created) || a.name.localeCompare(b.name),
  );
  page = Math.min(page, Math.max(0, Math.ceil(results.length / pageSize) - 1));
  count.textContent = `${results.length.toLocaleString()} of ${drivers.length.toLocaleString()} driver entries`;
  document
    .querySelectorAll<HTMLElement>('[data-category]')
    .forEach((b) =>
      b.setAttribute('aria-pressed', String(b.dataset.category === category)),
    );
  rows.innerHTML =
    results
      .slice(page * pageSize, (page + 1) * pageSize)
      .map(
        (d) =>
          `<tr><td><a class="filename" href="/drivers/${encodeURIComponent(d.id)}/${hash ? `?hash=${query}#samples` : ''}" title="${escapeHTML(d.name)}">${escapeHTML(d.name)} →</a><span class="publisher">${escapeHTML(d.publisher || 'Publisher not recorded')}</span></td><td><span class="badge ${d.category === 'malicious' ? 'malicious' : 'vulnerable'}">${d.category === 'malicious' ? 'Malicious' : 'Vulnerable'}</span></td><td class="cell-muted ${d.yes ? 'yes' : ''}">${d.unknown === d.samples ? 'Unknown' : `${d.yes} / ${d.samples} samples`}</td><td class="cell-muted">${d.samples}</td><td class="cell-muted">${escapeHTML(d.created)}</td></tr>`,
      )
      .join('') ||
    '<tr><td class="empty" colspan="5">No matching drivers. Try another hash or clear a filter.</td></tr>';
  document.getElementById('page-label')!.textContent = results.length
    ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, results.length)} of ${results.length}`
    : '0 results';
  previous.disabled = page === 0;
  next.disabled = (page + 1) * pageSize >= results.length;
  writeState();
}
async function load() {
  if (drivers) {
    render();
    return;
  }
  if (loading) return loading;
  error.hidden = true;
  loading = (async () => {
    try {
      const response = await fetch('/data/search.json');
      if (!response.ok) throw new Error('Search unavailable');
      drivers = await response.json();
      render();
    } catch {
      error.hidden = false;
    } finally {
      loading = undefined;
    }
  })();
  return loading;
}
readState();
void load();
document
  .getElementById('retry-search')
  ?.addEventListener('click', () => void load());
for (const element of [input, hvci, sort])
  element.addEventListener(element === input ? 'input' : 'change', () => {
    page = 0;
    void load();
  });
document.querySelectorAll<HTMLElement>('[data-category]').forEach((button) =>
  button.addEventListener('click', () => {
    category = button.dataset.category!;
    page = 0;
    void load();
  }),
);
previous.addEventListener('click', () => {
  page--;
  render();
});
next.addEventListener('click', () => {
  page++;
  render();
});
window.addEventListener('popstate', () => {
  readState();
  void load();
});
document.addEventListener('keydown', (event) => {
  if (
    event.key === '/' &&
    !['INPUT', 'TEXTAREA', 'SELECT'].includes(
      document.activeElement?.tagName || '',
    )
  ) {
    event.preventDefault();
    input.focus();
  }
});
