const requiredText = (value) => typeof value === 'string' && value.trim().length > 0;

// One record for an engagement. Payment is a placeholder. Nothing here charges a card.
export const createOrder = (input) => {
  if (!requiredText(input?.id)) throw new Error('Order id is required');
  if (!requiredText(input?.customer?.name)) throw new Error('Customer name is required');
  if (!requiredText(input?.target)) throw new Error('Order target is required');
  return {
    id: input.id.trim(),
    customer: { name: input.customer.name.trim() },
    target: input.target.trim(),
    ownership: {
      ok: input.ownership?.ok === true,
      method: input.ownership?.method || null,
      at: input.ownership?.at || null,
      tokenHint: input.ownership?.tokenHint || null,
    },
    authorisation: {
      granted: input.authorisation?.granted === true,
      at: input.authorisation?.at || null,
      reference: input.authorisation?.reference || null,
    },
    signOff: input.signOff?.reviewer
      ? {
          reviewer: input.signOff.reviewer,
          at: input.signOff.at || null,
          status: input.signOff.status || null,
        }
      : null,
    payment: {
      status: 'not-integrated',
      provider: null,
    },
    reportRelease: null,
  };
};

export const releaseBlockers = (order) => {
  const missing = [];
  if (order?.ownership?.ok !== true) missing.push('ownership');
  if (order?.authorisation?.granted !== true) missing.push('authorisation');
  if (!order?.signOff?.reviewer || order.signOff.status !== 'released') missing.push('sign-off');
  return missing;
};

export const releaseOrder = (order, report) => {
  const missing = releaseBlockers(order);
  if (report?.release?.status !== 'released') missing.push('report-sign-off');
  if (missing.length) return { ok: false, missing, order };
  return {
    ok: true,
    order: {
      ...order,
      payment: { status: 'not-integrated', provider: null },
      reportRelease: {
        status: 'released',
        at: report.release.at || report.generatedAt,
        reviewer: report.release.reviewer || order.signOff.reviewer,
      },
    },
  };
};
