// TuResto Print Agent - lib/rateLimiter.js
//
// Rate limit por endpoint + IP, en memoria. Antes solo /pair/verify tenía
// límite (ver pairing.js) — /print, /printers y /jobs eran ilimitados: con el
// Bearer token en mano (robado del localStorage, por ej.), un atacante podía
// spammear miles de impresiones por segundo y agotar papel/tóner sin freno.
//
// Bucket simple en memoria (no hace falta persistir entre reinicios: un
// reinicio del agente ya es una "ventana nueva" razonable).

const log = require('./logger');

const LIMITS = {
  '/pair/verify': { max: 5, windowMs: 60_000 },
  '/pair/code': { max: 30, windowMs: 60_000 },
  '/print': { max: 30, windowMs: 60_000 },
  '/printers': { max: 20, windowMs: 60_000 },
  '/jobs': { max: 60, windowMs: 60_000 },
  '/health': { max: 120, windowMs: 60_000 },
  default: { max: 60, windowMs: 60_000 },
};

// path -> ip -> { count, windowStart }
const buckets = new Map();

function getLimit(path) {
  return LIMITS[path] || LIMITS.default;
}

function rateLimit(req, res, next) {
  const path = req.path;
  const limit = getLimit(path);
  const ip = req.ip || req.socket.remoteAddress || 'unknown';

  let perPath = buckets.get(path);
  if (!perPath) {
    perPath = new Map();
    buckets.set(path, perPath);
  }

  const now = Date.now();
  let entry = perPath.get(ip);
  if (!entry || now - entry.windowStart > limit.windowMs) {
    entry = { count: 0, windowStart: now };
    perPath.set(ip, entry);
  }
  entry.count++;

  res.set('X-RateLimit-Limit', String(limit.max));
  res.set('X-RateLimit-Remaining', String(Math.max(0, limit.max - entry.count)));
  res.set('X-RateLimit-Reset', String(Math.ceil((entry.windowStart + limit.windowMs) / 1000)));

  if (entry.count > limit.max) {
    const retryAfter = Math.ceil((entry.windowStart + limit.windowMs - now) / 1000);
    log.warn(`Rate limit excedido en ${path} desde ${ip} (${entry.count}/${limit.max})`);
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({ success: false, error: 'Demasiadas solicitudes. Esperá un minuto.' });
  }

  next();
}

// Limpieza periódica: sin esto, cada IP que alguna vez pegó queda viva para
// siempre en memoria — en un proceso de fondo de larga duración (días/semanas
// sin reiniciar) esto crecería sin límite.
const CLEANUP_INTERVAL_MS = 5 * 60_000;
const STALE_AFTER_MS = 10 * 60_000;
setInterval(() => {
  const now = Date.now();
  for (const [path, perPath] of buckets.entries()) {
    for (const [ip, entry] of perPath.entries()) {
      if (now - entry.windowStart > STALE_AFTER_MS) perPath.delete(ip);
    }
    // También se borra la RUTA cuando queda vacía. Este middleware corre con
    // `app.use`, o sea ANTES del ruteo: entra CUALQUIER path, exista o no. La
    // limpieza de arriba vaciaba el mapa interno pero dejaba la entrada de la
    // ruta viva para siempre, así que cualquier cosa que pruebe rutas al azar
    // (/a1, /a2, /a3…) sumaba un Map vacío por cada una, sin techo. Es la misma
    // fuga que ya se corrigió del lado del backend con RateLimitPurga, un nivel
    // más arriba. El agente corre semanas sin reiniciarse, que es justo donde
    // este tipo de goteo se nota.
    if (perPath.size === 0) buckets.delete(path);
  }
}, CLEANUP_INTERVAL_MS).unref();

module.exports = { rateLimit };
