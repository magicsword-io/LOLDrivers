export interface GrowthPoint {
  month: string;
  added: number;
  total: number;
}

// Count current catalog entries by their recorded creation date, not sample
// timestamps or modification dates. Missing months contribute no new entries.
export function catalogGrowth(entries: { created: string }[]) {
  const additions = new Map<string, number>();
  let undated = 0;
  for (const { created } of entries) {
    const timestamp = Date.parse(created);
    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(created) ||
      !Number.isFinite(timestamp) ||
      new Date(timestamp).toISOString().slice(0, 10) !== created
    ) {
      undated++;
      continue;
    }
    const month = created.slice(0, 7);
    additions.set(month, (additions.get(month) || 0) + 1);
  }

  const months = [...additions.keys()].sort();
  const points: GrowthPoint[] = [];
  if (!months.length) return { points, undated };

  const cursor = new Date(`${months[0]}-01T00:00:00Z`);
  let total = 0;
  while (cursor.toISOString().slice(0, 7) <= months[months.length - 1]) {
    const month = cursor.toISOString().slice(0, 7);
    const added = additions.get(month) || 0;
    total += added;
    points.push({ month, added, total });
    cursor.setUTCMonth(cursor.getUTCMonth() + 1);
  }
  return { points, undated };
}
