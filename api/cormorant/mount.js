import express from 'express';
import { createRouter } from './router.js';

export const mountCormorant = (app, opts = {}) => {
  try {
    const router = createRouter(opts);
    app.use('/api/v1', express.json({ limit: '12mb' }), router);
    return router;
  } catch (error) {
    console.error('Cormorant OSINT desk failed to mount', error);
    return null;
  }
};
