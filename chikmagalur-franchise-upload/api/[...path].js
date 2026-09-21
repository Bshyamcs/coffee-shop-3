'use strict';
// Catch-all entry (kept alongside api/index.js as a safety net; vercel.json rewrites also target index.js)
const { handle } = require('../lib/app');

module.exports = (req, res) => handle(req, res);
