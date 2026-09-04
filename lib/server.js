// TuResto Print Agent - lib/server.js
//
// Servidor Express en 127.0.0.1:47823.
//
// Endpoints:
//  GET  /health           - Sin auth. Estado del agente (incluye vencimiento del token).
//  POST /pair/verify       - Sin auth (rate limited + lockout). Código de 6 dígitos -> token.
//  GET  /pair/claim         - Sin auth. La pestaña que disparó turesto://pair lo
//                             pollea hasta que el agente confirma el auto-pairing.
//  POST /quit                - Sin auth. Apaga el agente — no hay bandeja ni
//                             ventana, así que sin esto la única forma de
//                             cerrarlo sería el Administrador de tareas.
//  GET  /printers          - Bearer. Impresoras instaladas en Windows.
//  GET  /printer-config     - Bearer. Ancho de rollo detectado (best-effort) de una impresora.
//  POST /print              - Bearer. Valida el HTML y encola un ticket para imprimir.
//  POST /auth/refresh       - Bearer. Extiende 30 días más el token actual.
//  GET  /audit/prints       - Bearer. Historial de impresiones (filtros: from/to/printer/failed).
//  GET  /audit/prints/stats - Bearer. Totales + desglose por impresora.
//  GET  /audit/pairing      - Bearer. Historial de intentos de pairing.
//  GET  /jobs, /jobs/:id    - Bearer. Estado de la cola.
//  DELETE /jobs             - Bearer. Limpia jobs completados/fallidos.
//
// Seguridad: CORS por allowlist (web + extension ID), Bearer token de 256
// bits con expiración a 30 días, comparación en tiempo constante, rate limit
// por endpoint (todos, no solo pairing), lockout de pairing tras 5 fallos,
// validación de HTML antes de imprimir, audit log persistente, validación
// de Origin.

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { app: electronApp } = require('electron');
const config = require('./config');
const pairing = require('./pairing');
const queue = require('./queue');
const audit = require('./audit');
const { rateLimit } = require('./rateLimiter');
const { validateHtml, validateCopies } = require('./htmlValidator');
const { detectarAnchoPapel } = require('./paperDetect');
const log = require('./logger');

const VERSION = require('../package.json').version;

// Orden de intento: primero el que funcionó la última vez (así una PC que ya
// resolvió el conflicto no vuelve a barrer toda la lista en cada arranque),
// después el resto. PRINT_AGENT_PORT fuerza uno solo, sin fallback: es para
// debugging, y ahí querés que falle fuerte si no está libre.
function puertosAIntentar() {
  const forzado = Number(process.env.PRINT_AGENT_PORT);
  if (forzado) return [forzado];
  const ultimo = Number(config.get('port', config.DEFAULT_PORT));
  return [ultimo, ...config.PUERTOS_CANDIDATOS.filter((p) => p !== ultimo)];
}

function tokensEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

function authMiddleware(req, res, next) {
  // getPairedToken() ya devuelve null si venció (y limpia el store) — el
  // mismo código 503 "no vinculado" cubre "nunca se vinculó" y "se venció",
  // ambos requieren el mismo paso del usuario (volver a vincular).
  const expectedToken = config.getPairedToken();
  if (!expectedToken) {
    return res.status(503).json({ success: false, error: 'El agente no está vinculado. Generá un código de pairing primero.', code: 'NOT_PAIRED' });
  }
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, error: 'Falta token de autenticación', code: 'NO_TOKEN' });
  }
  const token = authHeader.slice(7);
  if (!tokensEqual(token, expectedToken)) {
    log.warn(`Token inválido desde ${req.ip}`);
    return res.status(403).json({ success: false, error: 'Token inválido', code: 'INVALID_TOKEN' });
  }

  // A <7 días de vencer: avisar en headers para que el front refresque solo
  // (ver POST /auth/refresh más abajo) sin esperar a que el token muera.
  const expiresAt = config.getTokenExpiresAt();
  if (expiresAt) {
    const daysLeft = Math.floor((expiresAt - Date.now()) / 86_400_000);
    if (daysLeft <= 7) {
      res.set('X-Token-Expires-Warning', String(daysLeft));
      res.set('X-Token-Expires-At', new Date(expiresAt).toISOString());
    }
  }

  next();
}

function originCheck(req, res, next) {
  const origin = req.headers.origin;
  if (origin && !config.isAllowedOrigin(origin)) {
    log.warn(`Origin no permitido: ${origin}`);
    return res.status(403).json({ success: false, error: 'Origen no permitido' });
  }
  next();
}

function startServer() {
  return new Promise((resolve, reject) => {
    const app = express();

    // Private Network Access (Chrome): una página pública HTTPS (turesto.pro)
    // que le pega a 127.0.0.1 dispara un preflight con el header
    // Access-Control-Request-Private-Network — si la respuesta no confirma
    // Access-Control-Allow-Private-Network, Chrome bloquea el request ANTES
    // de que llegue acá, sin ningún error visible del lado del agente. Esta
    // es la causa real de "el agente corre en background pero el navegador
    // nunca lo detecta" en versiones de Chrome que ya exigen esto — el
    // paquete `cors` de abajo no conoce este header todavía, así que se
    // contesta acá antes de que cors() arme la respuesta del preflight.
    app.use((req, res, next) => {
      if (req.headers['access-control-request-private-network']) {
        res.set('Access-Control-Allow-Private-Network', 'true');
      }
      next();
    });

    app.use(cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        if (config.isAllowedOrigin(origin)) return callback(null, true);
        callback(new Error('Not allowed by CORS'));
      },
      methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      maxAge: 86400,
    }));
    app.use(express.json({ limit: '15mb' }));
    app.use(originCheck);
    app.use(rateLimit); // ← Fix 1: aplica a TODOS los endpoints, no solo /pair/verify

    app.get('/health', (req, res) => {
      const expiresAt = config.getTokenExpiresAt();
      res.json({
        success: true,
        data: {
          status: 'ok',
          version: VERSION,
          port: config.get('port', config.DEFAULT_PORT),
          paired: !!config.getPairedToken(),
          tokenExpiresAt: expiresAt ? new Date(expiresAt).toISOString() : null,
          tokenExpired: config.isTokenExpired(),
          machine: config.get('machineName'),
          uptime: process.uptime(),
          timestamp: new Date().toISOString(),
        },
      });
    });

    app.post('/pair/verify', (req, res) => {
      const { code } = req.body || {};
      const result = pairing.verifyAndPair(code);
      audit.logPairingAttempt({
        ip: req.ip,
        success: result.success,
        error: result.error,
        userAgent: req.headers['user-agent'],
      });
      if (result.success) res.json({ success: true, token: result.token, machine: config.get('machineName') });
      else res.status(400).json({ success: false, error: result.error });
    });

    // La pestaña que disparó turesto://pair pollea esto en vez de esperar un
    // redirect — devuelve éxito UNA sola vez (claimPendingAutoPair lo borra al
    // leerlo), success:false mientras no haya nada o ya se haya reclamado.
    app.get('/pair/claim', (req, res) => {
      const claim = pairing.claimPendingAutoPair();
      if (!claim) return res.json({ success: false });
      res.json({ success: true, token: claim.token, machine: claim.machine });
    });

    // El código de 6 dígitos existía desde el principio (pairing.js) pero
    // nada lo mostraba: este agente no tiene tray ni ventana (rediseño a
    // pedido explícito, ver main.js), y la UI web decía "mirá el ícono en la
    // bandeja" — un ícono que no existe. Si turesto://pair falla (protocolo
    // no registrado, navegador que lo bloquea), el pairing manual quedaba sin
    // ninguna forma real de completarse. Mismo criterio de alcance que
    // /health: solo responde en 127.0.0.1, y ya pasa por CORS/originCheck
    // como el resto — el código en sí no es más sensible que /health (nadie
    // fuera de esta PC llega a pedirlo).
    app.get('/pair/code', (req, res) => {
      res.json({ success: true, code: pairing.getCurrentCode(), expiresInMs: pairing.getCodeRemainingMs() });
    });

    app.use(authMiddleware);

    // Sin bandeja ni ventana, esta es la única forma de cerrar el agente sin
    // el Administrador de tareas. Movido detrás de authMiddleware (auditoría
    // de seguridad): nada del front lo llama sin token igual, y sin esto
    // cualquier pestaña abierta en el mismo navegador (ajena a TuResto)
    // podía apagar el agente con un POST simple sin preflight — Bearer
    // token real, no solo el chequeo de Origin de más abajo.
    app.post('/quit', (req, res) => {
      res.json({ success: true });
      log.info('Apagando agente por pedido remoto (POST /quit).');
      setTimeout(() => electronApp.quit(), 100);
    });

    app.get('/printers', async (req, res) => {
      try {
        const printers = await queue.listPrinters();
        res.json({ success: true, printers: printers.map((p) => ({ name: p.name, default: !!p.isDefault })) });
      } catch (err) {
        log.error('Error listando impresoras:', err);
        res.status(500).json({ success: false, error: err.message });
      }
    });

    // Ancho de rollo best-effort para UNA impresora — endpoint aparte de
    // /printers (no en el hot path del polling) porque dispara PowerShell,
    // que puede tardar unos segundos. Pensado para un botón "Detectar
    // automáticamente" que el dueño confirma, ver PrintAppearance.jsx.
    app.get('/printer-config', async (req, res) => {
      const name = req.query.name;
      if (!name) return res.status(400).json({ success: false, error: 'Falta el parámetro name.' });
      try {
        const printers = await queue.listPrinters();
        const match = printers.find((p) => p.name === name);
        const driverInfo = match?.options?.['printer-make-and-model'] || '';
        const resultado = await detectarAnchoPapel(name, driverInfo);
        res.json({ success: true, ...resultado });
      } catch (err) {
        log.error('Error detectando ancho de papel:', err);
        res.status(500).json({ success: false, error: err.message });
      }
    });

    app.post('/print', (req, res) => {
      const { html, printerName, copies } = req.body || {};
      const origin = req.headers.origin?.startsWith('chrome-extension') ? 'extension' : 'web';
      if (!printerName) return res.status(400).json({ success: false, error: 'Falta printerName' });

      // Fix 4: validar el HTML antes de encolar (tamaño, markup real, sin
      // <script>/iframes/recursos remotos). Falla acá, no en processJob —
      // un payload malicioso/corrupto ni siquiera entra a la cola persistida.
      let copiesValidated;
      try {
        validateHtml(html);
        copiesValidated = validateCopies(copies);
      } catch (err) {
        log.warn(`/print rechazado: ${err.message}`);
        audit.logPrintJob({ printerName, origin, success: false, error: `Validación: ${err.message}`, html, metadata: req.body.metadata });
        return res.status(400).json({ success: false, error: err.message });
      }

      try {
        const job = queue.addJob({ html, printerName, copies: copiesValidated });
        audit.logPrintJob({ printerName, origin, success: true, jobId: job.id, html, metadata: req.body.metadata });
        res.json({ success: true, jobId: job.id, status: job.status });
      } catch (err) {
        log.error('Error encolando job:', err);
        audit.logPrintJob({ printerName, origin, success: false, error: err.message, html, metadata: req.body.metadata });
        res.status(500).json({ success: false, error: err.message });
      }
    });

    // Fix 5: renovar el token actual (mismo valor, nuevo vencimiento) sin
    // tener que re-vincular — el front lo llama solo cuando ve
    // X-Token-Expires-Warning en una respuesta (ver authMiddleware).
    app.post('/auth/refresh', (req, res) => {
      try {
        const { token, expiresAt } = config.refreshToken();
        log.info('Token refrescado por solicitud del cliente.');
        res.json({ success: true, token, expiresAt: new Date(expiresAt).toISOString() });
      } catch (err) {
        res.status(400).json({ success: false, error: err.message });
      }
    });

    // Fix 3: consulta del historial de auditoría — protegido igual que el
    // resto (Bearer), no expuesto sin auth.
    app.get('/audit/prints', (req, res) => {
      const { from, to, limit, offset, printer, failed } = req.query;
      const result = audit.getPrintAuditLogs({
        from, to,
        limit: limit ? Number(limit) : undefined,
        offset: offset ? Number(offset) : undefined,
        printerName: printer,
        failedOnly: failed === 'true',
      });
      res.json({ success: true, ...result });
    });

    app.get('/audit/prints/stats', (req, res) => {
      const { from, to } = req.query;
      res.json({ success: true, stats: audit.getAuditStats({ from, to }) });
    });

    app.get('/audit/pairing', (req, res) => {
      const { from, to, limit } = req.query;
      res.json({ success: true, logs: audit.getPairingAuditLogs({ from, to, limit: limit ? Number(limit) : undefined }) });
    });

    app.get('/jobs', (req, res) => res.json({ success: true, jobs: queue.getAllJobs() }));

    app.get('/jobs/:id', (req, res) => {
      const job = queue.getJob(req.params.id);
      if (!job) return res.status(404).json({ success: false, error: 'Job no encontrado' });
      res.json({ success: true, job });
    });

    app.delete('/jobs', (req, res) => {
      queue.clearCompleted();
      res.json({ success: true });
    });

    // Manejador de errores propio. Sin esto, el error que tira cors() para un
    // origen no permitido caía en el handler por default de Express, que
    // responde 500 con el STACK TRACE completo en el body (Express está en
    // modo development salvo que NODE_ENV diga otra cosa, y en un Electron
    // empaquetado no lo dice). O sea: una página que ya iba a ser rechazada
    // igual se llevaba de yapa las rutas del disco de la PC del bar. Y encima
    // el código quedaba en 500 —"el agente se rompió"— cuando la respuesta
    // correcta es 403, que es lo que ya devuelve originCheck para el mismo
    // caso cuando llega a ejecutarse.
    app.use((err, req, res, _next) => {
      if (err && /CORS/i.test(err.message || '')) {
        return res.status(403).json({ success: false, error: 'Origen no permitido' });
      }
      log.error('Error no manejado en el servidor HTTP:', err);
      res.status(500).json({ success: false, error: 'Error interno del agente' });
    });

    // Prueba puerto por puerto hasta encontrar uno libre. Solo EADDRINUSE
    // pasa al siguiente: cualquier otro error (permisos, stack de red rota)
    // no se arregla cambiando de puerto y conviene que falle de una.
    const puertos = puertosAIntentar();
    (function intentar(i) {
      if (i >= puertos.length) {
        const err = new Error(`Todos los puertos están ocupados (${puertos.join(', ')})`);
        err.code = 'EADDRINUSE';
        log.error(err.message);
        return reject(err);
      }
      const puerto = puertos[i];
      const server = app.listen(puerto, '127.0.0.1', () => {
        // Persistido para que el próximo arranque empiece por el que anduvo,
        // y para que /health lo reporte (la web lo usa para no re-sondear).
        if (config.get('port') !== puerto) config.set('port', puerto);
        log.info(`TuResto Print Agent escuchando en http://127.0.0.1:${puerto}`);
        resolve(server);
      });
      server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          log.warn(`Puerto ${puerto} ocupado, probando el siguiente.`);
          return intentar(i + 1);
        }
        log.error('Error en servidor HTTP:', err);
        reject(err);
      });
    })(0);
  });
}

module.exports = { startServer };
