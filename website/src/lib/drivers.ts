import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { parse } from 'yaml';
import { resolve, join } from 'node:path';

export type Metadata = Record<string, unknown>;
export interface RawDriver extends Metadata {
  Id: string;
  Tags: string[];
  Category: 'vulnerable driver' | 'malicious';
  KnownVulnerableSamples: Metadata[];
  Commands?: Metadata;
}
export interface DriverSummary {
  id: string;
  name: string;
  publisher: string;
  category: RawDriver['Category'];
  created: string;
  description: string;
  verified: boolean;
  samples: number;
  yes: number;
  no: number;
  unknown: number;
  search: string;
}

export const text = (value: unknown): string =>
  typeof value === 'string' ? value.trim() : '';
export function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.flatMap(strings)
    : text(value)
      ? [text(value)]
      : [];
}
export function object(value: unknown): Metadata {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Metadata)
    : {};
}
export const status = (value: unknown) =>
  value === true || text(value).toUpperCase() === 'TRUE'
    ? 'yes'
    : value === false || text(value).toUpperCase() === 'FALSE'
      ? 'no'
      : 'unknown';
export function safeUrl(value: unknown): string | undefined {
  try {
    const url = new URL(text(value));
    return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}

// Build-time only: never import the full catalog into client scripts.
const directory = resolve(process.cwd(), '../yaml');
const seen = new Set<string>();
export const rawDrivers: RawDriver[] = readdirSync(directory)
  .filter((name) => name.endsWith('.yaml'))
  .sort()
  .map((name) => {
    const raw = parse(readFileSync(join(directory, name), 'utf8')) as RawDriver;
    if (
      !raw ||
      raw.Id !== name.slice(0, -5) ||
      !/^[a-f0-9-]{36}$/i.test(raw.Id) ||
      seen.has(raw.Id) ||
      !Array.isArray(raw.Tags) ||
      !raw.Tags.length ||
      !Array.isArray(raw.KnownVulnerableSamples) ||
      !['malicious', 'vulnerable driver'].includes(raw.Category)
    ) {
      throw new Error(`Invalid driver catalog entry: ${name}`);
    }
    seen.add(raw.Id);
    return raw;
  });

export function summarize(raw: RawDriver): DriverSummary {
  const samples = raw.KnownVulnerableSamples;
  const publishers = [
    ...new Set(
      samples.flatMap((s) =>
        ['Publisher', 'Company', 'CompanyName'].flatMap((k) => strings(s[k])),
      ),
    ),
  ].sort();
  const sampleTerms = samples.flatMap((s) => [
    ...[
      'Filename',
      'OriginalFilename',
      'MD5',
      'SHA1',
      'SHA256',
      'Imphash',
      'Product',
      'ProductName',
    ].flatMap((k) => strings(s[k])),
    ...Object.values(object(s.Authentihash)).flatMap(strings),
  ]);
  const yes = samples.filter(
    (s) => status(s.LoadsDespiteHVCI) === 'yes',
  ).length;
  const no = samples.filter((s) => status(s.LoadsDespiteHVCI) === 'no').length;
  return {
    id: raw.Id,
    name: raw.Tags[0],
    publisher: publishers[0] || '',
    category: raw.Category,
    created: text(raw.Created),
    description: text(raw.Commands?.Description),
    verified: status(raw.Verified) === 'yes',
    samples: samples.length,
    yes,
    no,
    unknown: samples.length - yes - no,
    search: [
      ...new Set([
        raw.Id,
        ...raw.Tags,
        ...publishers,
        ...sampleTerms,
        ...strings(raw.CVE),
        ...strings(raw.CVEs),
      ]),
    ]
      .join(' ')
      .toLowerCase(),
  };
}
export const drivers = rawDrivers
  .map(summarize)
  .sort(
    (a, b) =>
      b.created.localeCompare(a.created) || a.name.localeCompare(b.name),
  );
export const totals = {
  entries: drivers.length,
  samples: drivers.reduce((n, d) => n + d.samples, 0),
  yes: drivers.reduce((n, d) => n + d.yes, 0),
  unknown: drivers.reduce((n, d) => n + d.unknown, 0),
};
export const driverPath = (id: string) => `/drivers/${encodeURIComponent(id)}/`;

export function sampleDownload(sample: Metadata): string | undefined {
  const md5 = text(sample.MD5).toLowerCase();
  if (!/^[a-f0-9]{32}$/.test(md5)) return undefined;
  if (!existsSync(resolve(process.cwd(), '../drivers', `${md5}.bin`)))
    return undefined;
  return `https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/${md5}.bin`;
}
