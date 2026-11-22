(() => {
  'use strict';
  const announcer = document.getElementById('announcer');
  const docsMenu = document.querySelector('.docs-menu');
  if (docsMenu && window.matchMedia) {
    const narrow = window.matchMedia('(max-width: 760px)');
    const sync = () => { docsMenu.open = !narrow.matches; };
    sync();
    narrow.addEventListener?.('change', sync);
  }

  document.querySelectorAll('[data-copy]').forEach(button => {
    button.addEventListener('click', async () => {
      const code = document.getElementById(button.dataset.copy);
      const initial = button.textContent;
      try {
        await navigator.clipboard.writeText(code.textContent.trim());
        button.textContent = 'Copied ✓';
        if (announcer) announcer.textContent = 'Command copied to clipboard.';
      } catch {
        const range = document.createRange();
        range.selectNodeContents(code);
        const selection = window.getSelection();
        selection.removeAllRanges(); selection.addRange(range);
        button.textContent = 'Selected — copy manually';
        if (announcer) announcer.textContent = 'Clipboard unavailable. Command selected for manual copying.';
      }
      window.setTimeout(() => { button.textContent = initial; }, 2500);
    });
  });
  document.querySelectorAll('[data-carousel]').forEach(carousel => {
    const track = carousel.querySelector('.slides');
    const slides = [...track.querySelectorAll('.slide')];
    const dots = carousel.querySelector('.dots');
    const current = () => Math.round(track.scrollLeft / track.clientWidth);
    const go = i => track.scrollTo({ left: ((i + slides.length) % slides.length) * track.clientWidth });
    slides.forEach((slide, i) => {
      const dot = document.createElement('button');
      dot.type = 'button'; dot.setAttribute('role', 'tab');
      dot.setAttribute('aria-label', slide.querySelector('figcaption')?.textContent || 'Screenshot ' + (i + 1));
      dot.addEventListener('click', () => go(i));
      dots.append(dot);
    });
    const sync = () => dots.querySelectorAll('button').forEach((d, i) => d.setAttribute('aria-selected', String(i === current())));
    track.addEventListener('scroll', () => window.requestAnimationFrame(sync), { passive: true });
    carousel.querySelector('[data-prev]').addEventListener('click', () => go(current() - 1));
    carousel.querySelector('[data-next]').addEventListener('click', () => go(current() + 1));
    track.addEventListener('keydown', event => {
      if (event.key === 'ArrowRight') { event.preventDefault(); go(current() + 1); }
      if (event.key === 'ArrowLeft') { event.preventDefault(); go(current() - 1); }
    });
    sync();
  });

  const input = document.getElementById('docs-search');
  const results = document.getElementById('search-results');
  if (!input || !results) return;
  let index;
  let loading;
  async function search() {
    const query = input.value.trim().toLocaleLowerCase();
    results.replaceChildren(); results.hidden = !query;
    if (!query) return;
    try {
      loading ??= fetch(input.dataset.index).then(response => {
        if (!response.ok) throw new Error('Search index unavailable');
        return response.json();
      });
      index ??= await loading;
      if (input.value.trim().toLocaleLowerCase() !== query) return;
      const terms = query.split(/\s+/);
      const matches = index.map(item => {
        const title = item.title.toLocaleLowerCase();
        const text = item.text.toLocaleLowerCase();
        if (!terms.every(term => (title + ' ' + text).includes(term))) return null;
        const score = terms.reduce((sum, term) => sum + (title.includes(term) ? 20 : 0) + Math.min(text.split(term).length - 1, 8), 0)
          + (item.url.includes('/troubleshooting/') ? 5 : 0);
        return { ...item, score };
      }).filter(Boolean).sort((a, b) => b.score - a.score).slice(0, 8);
      for (const item of matches) {
        const link = document.createElement('a'); link.href = item.url; link.textContent = item.title; results.append(link);
      }
      if (!matches.length) results.textContent = 'No matches. Try “reboot”, “password” or “DHCP”.';
      if (announcer) announcer.textContent = `${matches.length} documentation results.`;
    } catch {
      loading = undefined;
      results.textContent = 'Search is unavailable. The documentation links below still work.';
    }
  }
  input.addEventListener('input', search);
  input.addEventListener('keydown', event => {
    if (event.key === 'Escape') { input.value = ''; results.hidden = true; input.blur(); }
    if (event.key === 'ArrowDown') { const first = results.querySelector('a'); if (first) { event.preventDefault(); first.focus(); } }
  });
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase() === 'k') { event.preventDefault(); input.focus(); }
  });
})();
