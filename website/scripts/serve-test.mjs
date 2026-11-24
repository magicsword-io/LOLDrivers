import { preview } from 'astro';

// Keep the test server in the foreground, including in agent environments.
const port = Number(process.env.PLAYWRIGHT_PORT || '4321');
const server = await preview({ server: { host: '127.0.0.1', port } });
process.on('SIGTERM', async () => {
  await server.stop();
  process.exit(0);
});
