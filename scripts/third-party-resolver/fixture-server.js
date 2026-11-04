// Minimal HTTPS file server run inside a container by run.js (M-17). Serves /data/logs/<url path> on 8443.
const fs = require('fs');
const https = require('https');
const path = require('path');

https
  .createServer({ key: fs.readFileSync('/data/key.pem'), cert: fs.readFileSync('/data/cert.pem') }, (req, res) => {
    const file = path.join('/data/logs', path.normalize(req.url).replace(/^(\.\.[/\\])+/, ''));
    fs.readFile(file, (err, body) => {
      if (err) { res.writeHead(404).end(); return; }
      res.writeHead(200, { 'content-type': 'text/jsonl' }).end(body);
    });
  })
  .listen(8443, '0.0.0.0', () => console.log('fixture server ready'));
