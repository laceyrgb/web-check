import { normaliseIntel } from '../intel/intel.js';

// Fixture-backed NVD ingestion. This object has no API key and does not open a socket.
export const createNvdProvider = ({ fixture } = {}) => ({
  id: 'fixture-stub',
  apiKey: null,
  async ingest() {
    if (!fixture) throw new Error('NVD stub needs a fixture payload');
    return normaliseIntel(fixture);
  },
});
