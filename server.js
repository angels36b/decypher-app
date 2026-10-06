// ============================================================
// Importamos los módulos nativos de Node.js
// ============================================================

const http = require('node:http');
const crypto = require('node:crypto');
const BusBoy = require('busboy');

// ============================================================
// Configuración
// ============================================================

const LOGIN = 'angel36b';
const PORT = process.env.PORT || 3000;

// ============================================================
// Creación del servidor
// ============================================================

const server = http.createServer((req, res) => {

  // ----------------------------------------------------------
  // Normalizamos la URL: quitamos query string y barra final
  // ----------------------------------------------------------
  // Esto se hace UNA VEZ al principio, para que todas las rutas
  // comparen contra el mismo valor normalizado.
  const urlPath = req.url.split('?')[0].replace(/\/$/, '') || '/';

  // ----------------------------------------------------------
  // RUTA: GET /login
  // ----------------------------------------------------------
  if (req.method === 'GET' && urlPath === '/login') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(LOGIN);
    return;
  }

  // ----------------------------------------------------------
  // RUTA: POST /decrypher
  // ----------------------------------------------------------
  if (req.method === 'POST' && urlPath === '/decrypher') {

    const fields = {};
    const boy = BusBoy({ headers: req.headers });

    boy.on('file', (fieldname, file, info) => {
      const chunks = [];
      file.on('data', (data) => chunks.push(data));
      file.on('end', () => {
        fields[fieldname] = Buffer.concat(chunks);
      });
    });

    boy.on('finish', () => {
      const key = fields.key;
      const secret = fields.secret;

      if (!key || !secret) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Faltan key o secret');
        return;
      }

      try {
        const decrypted = crypto.privateDecrypt(
          {
            key: key,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
          },
          secret
        );

        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(decrypted.toString('utf-8'));

      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Error al descifrar: ' + e.message);
      }
    });

    req.pipe(boy);
    return;
  }

  // ----------------------------------------------------------
  // RUTA NO ENCONTRADA
  // ----------------------------------------------------------
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

// ============================================================
// Arranque del servidor
// ============================================================

server.listen(PORT, () => {
  console.log('Servidor escuchando en el puerto ' + PORT);
});