document
  .querySelectorAll<HTMLButtonElement>('[data-copy]')
  .forEach((button) => {
    let reset: ReturnType<typeof setTimeout> | undefined;
    const label = button.getAttribute('aria-label') || 'Copy hash';
    const title = button.title;
    button.addEventListener('click', async () => {
      clearTimeout(reset);
      delete button.dataset.copied;
      button.setAttribute('aria-label', label);
      button.title = title;
      const feedback = document.getElementById('copy-feedback')!;
      feedback.textContent = '';
      feedback.className = 'sr-only';
      try {
        await navigator.clipboard.writeText(button.dataset.copy || '');
        button.dataset.copied = 'true';
        button.setAttribute('aria-label', label.replace(/^Copy /, 'Copied '));
        button.title = 'Copied!';
        feedback.textContent = 'Hash copied to clipboard.';
        reset = setTimeout(() => {
          delete button.dataset.copied;
          button.setAttribute('aria-label', label);
          button.title = title;
        }, 1500);
      } catch {
        button.title = 'Copy unavailable. Select and copy the hash.';
        feedback.textContent =
          'Copy was unavailable. Select and copy the displayed hash.';
        feedback.className = 'sample-note';
      }
    });
  });

let record: Promise<{ KnownVulnerableSamples: unknown[] }> | undefined;
document
  .querySelectorAll<HTMLButtonElement>('[data-load-sample]')
  .forEach((button) =>
    button.addEventListener('click', async () => {
      const pre = document.getElementById(
        button.getAttribute('aria-controls')!,
      )!;
      if (pre.textContent) {
        pre.hidden = !pre.hidden;
        button.setAttribute('aria-expanded', String(!pre.hidden));
        button.textContent = pre.hidden
          ? 'Show full sample metadata'
          : 'Hide full sample metadata';
        return;
      }
      button.disabled = true;
      button.textContent = 'Loading metadata…';
      try {
        record ??= fetch(
          `/data/drivers/${encodeURIComponent(button.dataset.driverId!)}.json`,
        ).then((response) => {
          if (!response.ok) throw new Error('Metadata unavailable');
          return response.json();
        });
        const data = await record;
        pre.textContent = JSON.stringify(
          data.KnownVulnerableSamples[Number(button.dataset.loadSample)],
          null,
          2,
        );
        pre.hidden = false;
        button.setAttribute('aria-expanded', 'true');
        button.textContent = 'Hide full sample metadata';
      } catch {
        record = undefined;
        button.textContent = 'Retry loading metadata';
      } finally {
        button.disabled = false;
      }
    }),
  );

const hash = new URLSearchParams(location.search).get('hash')?.toLowerCase();
if (hash && /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(hash)) {
  const sample = [
    ...document.querySelectorAll<HTMLDetailsElement>('[data-hashes]'),
  ].find((element) => element.dataset.hashes?.split(' ').includes(hash));
  if (sample) {
    sample.open = true;
    sample.scrollIntoView({ block: 'start' });
  }
}
