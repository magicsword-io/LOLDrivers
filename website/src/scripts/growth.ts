interface PlotPoint {
  label: string;
  added: number;
  total: number;
  x: number;
  y: number;
}

document
  .querySelectorAll<HTMLElement>('[data-growth-chart]')
  .forEach((chart) => {
    const points: PlotPoint[] = JSON.parse(chart.dataset.points || '[]');
    if (!points.length) return;
    const plot = chart.querySelector<HTMLElement>('[data-growth-plot]')!;
    const svg = plot.querySelector('svg')!;
    const scrubber = chart.querySelector<HTMLInputElement>(
      '[data-growth-scrubber]',
    )!;
    const guide = chart.querySelector<SVGLineElement>('[data-growth-guide]')!;
    const dot = chart.querySelector<SVGCircleElement>('[data-growth-dot]')!;
    const month = chart.querySelector<HTMLElement>('[data-growth-month]')!;
    const total = chart.querySelector<HTMLElement>('[data-growth-total]')!;
    const added = chart.querySelector<HTMLElement>('[data-growth-added]')!;
    const format = (value: number) => value.toLocaleString('en-US');

    function select(index: number) {
      const point = points[index];
      scrubber.value = String(index);
      scrubber.setAttribute(
        'aria-valuetext',
        `${point.label}: ${format(point.total)} total driver entries, ${format(point.added)} added`,
      );
      month.textContent = point.label;
      total.textContent = format(point.total);
      added.textContent = `+${format(point.added)} added`;
      guide.setAttribute('x1', String(point.x));
      guide.setAttribute('x2', String(point.x));
      dot.setAttribute('cx', String(point.x));
      dot.setAttribute('cy', String(point.y));
    }

    function pointAt(event: PointerEvent) {
      const bounds = svg.getBoundingClientRect();
      const x =
        ((event.clientX - bounds.left) / bounds.width) *
        svg.viewBox.baseVal.width;
      const first = points[0].x;
      const span = points[points.length - 1].x - first;
      return span
        ? Math.max(
            0,
            Math.min(
              points.length - 1,
              Math.round(((x - first) / span) * (points.length - 1)),
            ),
          )
        : 0;
    }

    scrubber.hidden = false;
    scrubber.addEventListener('input', () => select(Number(scrubber.value)));
    plot.addEventListener('pointermove', (event) => select(pointAt(event)));
    plot.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      // Keep the subsequent mouse event from blurring the keyboard control,
      // which would reset a month selected by a click or touch tap.
      event.preventDefault();
      scrubber.focus({ preventScroll: true });
      select(pointAt(event));
    });
    plot.addEventListener('pointerleave', () => {
      if (document.activeElement !== scrubber) select(points.length - 1);
    });
    scrubber.addEventListener('blur', () => select(points.length - 1));
  });
