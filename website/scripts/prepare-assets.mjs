import { cp, mkdir } from 'node:fs/promises';

const source = new URL('../../loldrivers.io/static/', import.meta.url);
const target = new URL('../public/', import.meta.url);
await mkdir(new URL('images/', target), { recursive: true });
for (const name of [
  'logo.png',
  'logo-dark.png',
  'magicsword-logo-dark.png',
  'magicsword-logo-light.png',
]) {
  await cp(
    new URL(`images/${name}`, source),
    new URL(`images/${name}`, target),
  );
}
await cp(new URL('favicons/', source), new URL('favicons/', target), {
  recursive: true,
});
