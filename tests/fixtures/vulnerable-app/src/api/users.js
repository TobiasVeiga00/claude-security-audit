const express = require('express');
const router = express.Router();

// Vulnerable: request path value concatenated into SQL.
router.get('/users/:id', async (req, res) => {
  const row = await db.query('SELECT * FROM users WHERE id = ' + req.params.id);
  res.json(row);
});

// Vulnerable: user-controlled outbound request.
router.post('/fetch', async (req, res) => {
  const response = await fetch(req.body.targetUrl);
  res.send(await response.text());
});

module.exports = router;
