export const diffReports = (previous, current) => {
  const openOf = (report) =>
    new Map(
      (report?.findings || [])
        .filter((item) => item.status === 'open')
        .map((item) => [item.id, item]),
    );
  const before = openOf(previous);
  const after = openOf(current);
  const added = [];
  const removed = [];
  const unchanged = [];
  for (const [id, item] of after) {
    if (before.has(id)) unchanged.push(id);
    else added.push(item);
  }
  for (const [id, item] of before) {
    if (!after.has(id)) removed.push(item);
  }
  const prevScore = previous?.score?.value;
  const nextScore = current?.score?.value;
  return {
    added,
    removed,
    unchanged,
    scoreDelta:
      typeof prevScore === 'number' && typeof nextScore === 'number' ? nextScore - prevScore : null,
  };
};
