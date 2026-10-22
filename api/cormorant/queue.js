export const createQueue = (worker, { concurrency = 1 } = {}) => {
  const pending = [];
  const waiters = [];
  let active = 0;
  const drain = () => {
    if (active || pending.length) return;
    waiters.splice(0).forEach((resolve) => resolve());
  };
  const pump = () => {
    while (active < concurrency && pending.length) {
      const job = pending.shift();
      active += 1;
      Promise.resolve()
        .then(() => worker(job.task))
        .then(job.resolve, job.reject)
        .finally(() => {
          active -= 1;
          pump();
          drain();
        });
    }
  };
  return {
    push(task) {
      return new Promise((resolve, reject) => {
        pending.push({ task, resolve, reject });
        pump();
      });
    },
    whenIdle() {
      if (!active && !pending.length) return Promise.resolve();
      return new Promise((resolve) => waiters.push(resolve));
    },
  };
};

export const startScheduler = ({ store, enqueue }) => {
  const tick = () => {
    const now = Date.now();
    for (const monitor of store.listMonitors()) {
      if (!monitor.enabled || monitor.running) continue;
      if (monitor.nextRunAt && Date.parse(monitor.nextRunAt) > now) continue;
      const scan = store.createScan({
        target: monitor.target,
        hostname: monitor.hostname,
        email: monitor.email || null,
        publicUrls: monitor.publicUrls || [],
        monitorId: monitor.id,
      });
      store.updateMonitor(monitor.id, { running: true, lastScanId: scan.id });
      enqueue(scan.id);
    }
  };
  const timer = setInterval(() => {
    try {
      tick();
    } catch (error) {
      console.error('cormorant scheduler', error.message);
    }
  }, 60_000);
  timer.unref?.();
  return () => clearInterval(timer);
};
