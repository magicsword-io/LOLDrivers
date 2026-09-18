import type { APIRoute } from 'astro';
import { drivers } from '../lib/drivers';

const site = 'https://www.loldrivers.io';
const escapeXml = (value: string) =>
  value.replace(
    /[<>&"']/g,
    (character) =>
      ({
        '<': '&lt;',
        '>': '&gt;',
        '&': '&amp;',
        '"': '&quot;',
        "'": '&apos;',
      })[character]!,
  );
const pages = [
  '/',
  '/drivers/',
  '/about/',
  '/search/',
  '/detections/',
  '/tools/',
  '/api/',
];
const feeds = [
  'index.xml',
  'drivers/index.xml',
  'about/index.xml',
  'tags/index.xml',
  'categories/index.xml',
];

export function getStaticPaths() {
  return ['sitemap.xml', 'robots.txt', 'index.json', ...feeds].map(
    (legacy) => ({ params: { legacy } }),
  );
}

export const GET: APIRoute = ({ params }) => {
  const path = params.legacy!;
  if (path === 'robots.txt') {
    const production = import.meta.env.PUBLIC_SITE_MODE === 'production';
    return new Response(
      production
        ? `User-agent: *\nAllow: /\nSitemap: ${site}/sitemap.xml\n`
        : 'User-agent: *\nDisallow: /\n',
      { headers: { 'Content-Type': 'text/plain; charset=utf-8' } },
    );
  }
  if (path === 'index.json') {
    // Retain the legacy search endpoint and field names for existing consumers.
    return Response.json(
      drivers.map((driver) => ({
        body: `${driver.description}\n${driver.search}`,
        displayTitle: driver.name,
        link: `${site}/drivers/${driver.id}/`,
        section: 'drivers',
      })),
    );
  }
  let xml: string;
  if (path === 'sitemap.xml') {
    const routes = [
      ...pages,
      ...drivers.map((driver) => `/drivers/${driver.id}/`),
    ];
    xml = `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${routes.map((route) => `<url><loc>${site}${route}</loc></url>`).join('')}</urlset>`;
  } else {
    // Preserve feed URLs and stable UUID GUIDs. Empty legacy taxonomy/about feeds
    // remain valid channels; root and driver feeds contain the full catalog.
    const entries =
      path === 'index.xml' || path === 'drivers/index.xml' ? drivers : [];
    xml = `<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel><title>LOLDrivers</title><link>${site}/</link><description>Vulnerable and malicious Windows drivers</description><atom:link href="${site}/${path}" rel="self" type="application/rss+xml"/>${entries
      .map((driver) => {
        const url = `${site}/drivers/${driver.id}/`;
        const date = new Date(driver.created);
        return `<item><title>${escapeXml(driver.name)}</title><link>${url}</link><guid>${url}</guid>${Number.isNaN(date.valueOf()) ? '' : `<pubDate>${date.toUTCString()}</pubDate>`}<description>${escapeXml(driver.description)}</description></item>`;
      })
      .join('')}</channel></rss>`;
  }
  return new Response(`<?xml version="1.0" encoding="utf-8"?>${xml}`, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
