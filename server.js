// ============================================================
// Importamos los módulos nativos de Node.js
// ============================================================

// 'http' nos permite crear un servidor HTTP sin frameworks externos.
// Es la base sobre la que se construye todo lo demás.
const http = require('node:http');

// 'crypto' es el módulo nativo de criptografía de Node.js.
// Contiene 'privateDecrypt', que usaremos para descifrar con RSA.
const crypto = require('node:crypto');

// 'busboy' es una librería externa que parsea 'multipart/form-data'.
// La necesitamos porque el formulario envía dos archivos (key y secret).
// Node.js no tiene un parser nativo de multipart, así que usamos esta.
const BusBoy = require('busboy');

// ============================================================
// Configuración
// ============================================================

// El login que debemos devolver en la ruta /login.
// La tarea pide que sea el login del sistema MOODLE.
const LOGIN = 'angel36b';

// Render asigna el puerto mediante la variable de entorno PORT.
// Si no está definida (por ejemplo, en local), usamos 3000.
const PORT = process.env.PORT || 3000;

// ============================================================
// Creación del servidor
// ============================================================

const server = http.createServer((req, res) => {

  // ----------------------------------------------------------
  // RUTA: GET /login
  // ----------------------------------------------------------
  // La tarea pide que esta ruta devuelva el login en texto plano.
  // Solo aceptamos GET, porque es una consulta simple.
  if (req.method === 'GET' && req.url === '/login') {
    // Cabecera Content-Type: text/plain para que el navegador
    // muestre el texto sin interpretarlo como HTML.
    // charset=utf-8 para que los caracteres especiales se vean bien.
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });

    // Devolvemos el login como cuerpo de la respuesta.
    res.end(LOGIN);

    // Salimos de la función para no seguir procesando.
    return;
  }

  // ----------------------------------------------------------
  // RUTA: POST /decrypher
  // ----------------------------------------------------------
  // La tarea pide que esta ruta reciba dos archivos:
  //   - 'key': la clave privada RSA (formato PEM)
  //   - 'secret': el contenido cifrado (binario)
  // Y devuelva el resultado del descifrado como texto plano.
  if (req.method === 'POST' && req.url === '/decrypher') {

    // Objeto donde guardaremos los archivos recibidos.
    // Las claves serán 'key' y 'secret' (los nombres de los campos).
    const fields = {};

    // Creamos una instancia de BusBoy pasándole las cabeceras
    // de la petición. BusBoy necesita el 'Content-Type' para
    // saber que es 'multipart/form-data' y extraer el boundary.
    const boy = BusBoy({ headers: req.headers });

    // --------------------------------------------------------
    // Evento 'file': se dispara por cada archivo recibido.
    // --------------------------------------------------------
    // 'fieldname' es el nombre del campo del formulario ('key' o 'secret').
    // 'file' es un stream legible con el contenido del archivo.
    // 'info' contiene metadatos (nombre, tipo MIME, etc.).
    boy.on('file', (fieldname, file, info) => {

      // Acumulamos los trozos (chunks) del archivo en un array.
      // No podemos asumir que el archivo llega en un solo chunk.
      const chunks = [];

      // Cada vez que llega un trozo, lo guardamos.
      file.on('data', (data) => chunks.push(data));

      // Cuando el archivo termina de llegar, concatenamos
      // todos los chunks en un único Buffer y lo guardamos
      // en 'fields' bajo el nombre del campo.
      file.on('end', () => {
        fields[fieldname] = Buffer.concat(chunks);
      });
    });

    // --------------------------------------------------------
    // Evento 'finish': se dispara cuando BusBoy ha terminado
    // de parsear toda la petición.
    // --------------------------------------------------------
    boy.on('finish', () => {

      // Extraemos la clave privada y el contenido cifrado.
      const key = fields.key;
      const secret = fields.secret;

      // Si falta alguno de los dos, devolvemos un error 400.
      // Esto evita que el servidor intente descifrar sin datos.
      if (!key || !secret) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Faltan key o secret');
        return;
      }

      // ------------------------------------------------------
      // Descifrado con RSA
      // ------------------------------------------------------
      // Usamos 'crypto.privateDecrypt' porque:
      //   - Tenemos una clave PRIVADA (no pública).
      //   - Queremos DESCIFRAR (no cifrar).
      //
      // Parámetros:
      //   - key: la clave privada en formato PEM.
      //   - padding: RSA_PKCS1_OAEP_PADDING, el estándar moderno.
      //   - oaepHash: 'sha256', el hash usado dentro de OAEP.
      //
      // 'privateDecrypt' devuelve un Buffer con el texto descifrado.
      try {
        const decrypted = crypto.privateDecrypt(
          {
            key: key,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
          },
          secret
        );

        // Convertimos el Buffer a string UTF-8 y lo devolvemos.
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(decrypted.toString('utf-8'));

      } catch (e) {
        // Si el descifrado falla (clave incorrecta, padding incorrecto,
        // contenido corrupto, etc.), devolvemos un error 500 con el mensaje.
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Error al descifrar: ' + e.message);
      }
    });

    // --------------------------------------------------------
    // Conectamos el stream de la petición con BusBoy.
    // --------------------------------------------------------
    // Esto es CRUCIAL: sin 'req.pipe(boy)', BusBoy nunca recibiría
    // los datos de la petición y el evento 'finish' no se dispararía.
    // Es el equivalente a conectar una tubería entre la petición
    // entrante y el parser.
    req.pipe(boy);

    // Salimos para no seguir procesando.
    return;
  }

  // ----------------------------------------------------------
  // RUTA NO ENCONTRADA
  // ----------------------------------------------------------
  // Si la petición no coincide con ninguna ruta, devolvemos 404.
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

// ============================================================
// Arranque del servidor
// ============================================================

// Escuchamos en el puerto asignado por Render (o 3000 en local).
server.listen(PORT, () => {
  console.log('Servidor escuchando en el puerto ' + PORT);
});