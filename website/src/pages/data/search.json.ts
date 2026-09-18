import { drivers } from '../../lib/drivers';
export const GET = () =>
  new Response(JSON.stringify(drivers), {
    headers: { 'Content-Type': 'application/json' },
  });
