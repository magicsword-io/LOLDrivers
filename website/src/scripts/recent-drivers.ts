const carousel = document.querySelector<HTMLElement>('[data-recent-drivers]');

if (carousel) {
  const slides = [
    ...carousel.querySelectorAll<HTMLElement>('[data-recent-slide]'),
  ];
  const controls = carousel.querySelector<HTMLElement>(
    '[data-recent-controls]',
  )!;
  const position = carousel.querySelector<HTMLElement>(
    '[data-recent-position]',
  )!;
  const status = carousel.querySelector<HTMLElement>('[data-recent-status]')!;
  let current = 0;

  function showSlide(index: number) {
    current = (index + slides.length) % slides.length;
    slides.forEach((slide, i) => {
      slide.inert = i !== current;
      if (i === current) slide.removeAttribute('aria-hidden');
      else slide.setAttribute('aria-hidden', 'true');
    });
    position.textContent = `${current + 1} / ${slides.length}`;
    status.textContent = `Driver ${slides[current].getAttribute('aria-label')}`;
  }

  if (slides.length > 1) {
    controls.hidden = false;
    carousel
      .querySelector('[data-recent-previous]')
      ?.addEventListener('click', () => showSlide(current - 1));
    carousel
      .querySelector('[data-recent-next]')
      ?.addEventListener('click', () => showSlide(current + 1));
  }
}
