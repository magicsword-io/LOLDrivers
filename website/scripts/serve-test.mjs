import { preview } from 'astro';

// Keep the test server in the foreground, including in agent environments.
const server = await preview({ server: { host: '127.0.0.1', port: 4321 } });
process.on('SIGTERM', async () => {
  await server.stop();
  process.exit(0);
});
