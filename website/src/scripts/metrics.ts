const metrics = document.querySelector<HTMLElement>('[data-metrics]');

if (metrics) {
  const hvci = metrics.querySelector<HTMLElement>('[data-hvci-chart]')!;
  const ringValue = hvci.querySelector<HTMLElement>('[data-ring-value]')!;
  const ringLabel = hvci.querySelector<HTMLElement>('[data-ring-label]')!;
  const links = [
    ...hvci.querySelectorAll<HTMLAnchorElement>('[data-hvci-result]'),
  ];
  const segments = [
    ...hvci.querySelectorAll<SVGPathElement>('[data-ring-segment]'),
  ];

  function highlight(link: HTMLAnchorElement | null) {
    const selected = link || links[0];
    ringValue.textContent = selected.dataset.percent || '0.0';
    ringLabel.textContent = selected.dataset.label || '';
    if (link) hvci.dataset.highlight = link.dataset.hvciResult;
    else delete hvci.dataset.highlight;
    segments.forEach((segment) =>
      segment.classList.toggle(
        'is-active',
        segment.dataset.ringSegment === link?.dataset.hvciResult,
      ),
    );
  }

  links.forEach((link) => {
    link.addEventListener('mouseenter', () => highlight(link));
    link.addEventListener('mouseleave', () =>
      highlight(links.find((item) => item === document.activeElement) || null),
    );
    link.addEventListener('focus', () => highlight(link));
    link.addEventListener('blur', () => highlight(null));
  });

  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const animations = new Set<Animation>();
  const counters = [...metrics.querySelectorAll<HTMLElement>('[data-count]')];
  let frame = 0;
  const restoreCounts = () =>
    counters.forEach((counter) => {
      counter.textContent = Number(counter.dataset.count).toLocaleString(
        'en-US',
      );
    });
  function animate(
    element: Element,
    keyframes: Keyframe[],
    options: KeyframeAnimationOptions,
  ) {
    const animation = element.animate(keyframes, options);
    animations.add(animation);
    animation.addEventListener('finish', () => animations.delete(animation), {
      once: true,
    });
  }

  function reveal() {
    if (motion.matches) return;
    metrics!.querySelectorAll('.metric-card').forEach((card, index) => {
      animate(
        card,
        [
          { opacity: 0.4, transform: 'translateY(10px)' },
          { opacity: 1, transform: 'translateY(0)' },
        ],
        {
          duration: 650,
          delay: index * 90,
          easing: 'cubic-bezier(.2,.8,.2,1)',
          fill: 'backwards',
        },
      );
    });
    metrics!.querySelectorAll('[data-bar-reveal]').forEach((bar) => {
      animate(
        bar,
        [
          { transform: 'scaleX(0)', transformOrigin: 'left' },
          { transform: 'scaleX(1)', transformOrigin: 'left' },
        ],
        { duration: 1000, easing: 'cubic-bezier(.2,.8,.2,1)' },
      );
    });
    metrics!.querySelectorAll('[data-column-reveal]').forEach((bar, index) => {
      animate(
        bar,
        [
          { transform: 'scaleY(0)', transformOrigin: 'bottom' },
          { transform: 'scaleY(1)', transformOrigin: 'bottom' },
        ],
        {
          duration: 800,
          delay: index * 60,
          easing: 'cubic-bezier(.2,.8,.2,1)',
          fill: 'backwards',
        },
      );
    });
    metrics!.querySelectorAll('[data-ring-reveal]').forEach((ring) => {
      animate(ring, [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], {
        duration: 1100,
        easing: 'cubic-bezier(.2,.8,.2,1)',
      });
    });
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / 1100);
      const eased = 1 - Math.pow(1 - progress, 3);
      counters.forEach((counter) => {
        counter.textContent = Math.round(
          Number(counter.dataset.count) * eased,
        ).toLocaleString('en-US');
      });
      if (progress < 1) frame = requestAnimationFrame(tick);
      else restoreCounts();
    };
    frame = requestAnimationFrame(tick);
  }

  const observer = new IntersectionObserver(
    (entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      observer.disconnect();
      reveal();
    },
    { threshold: 0.15 },
  );
  observer.observe(metrics);
  motion.addEventListener('change', () => {
    if (!motion.matches) return;
    cancelAnimationFrame(frame);
    animations.forEach((animation) => animation.cancel());
    animations.clear();
    restoreCounts();
  });
}
