import type { APIRoute } from 'astro';
import { rawDrivers } from '../../../lib/drivers';
export function getStaticPaths() {
  return rawDrivers.map((driver) => ({
    params: { id: driver.Id },
    props: { driver },
  }));
}
export const GET: APIRoute = ({ props }) =>
  new Response(JSON.stringify(props.driver), {
    headers: { 'Content-Type': 'application/json' },
  });
