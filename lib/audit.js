// TuResto Print Agent - lib/audit.js
//
// Audit log de impresiones y pairing: sin esto, si alguien imprime contenido
// raro o miles de páginas no había forma de investigar qué pasó ni cuándo.
//
// POR QUÉ electron-store (JSON) y NO better-sqlite3: el resto del agente ya
// persiste todo así (config.js, queue.js) — agregar un módulo nativo (sqlite)
// significa que cada build de electron-builder tiene que recompilarlo para la
// versión exacta de Electron/Node-ABI del target, lo que es un punto de
// fallo real en este pipeline (instalador único, sin CI de multi-arch). Para
// el volumen de un agente de impresión de un solo local — decenas de jobs
// por día, no miles por segundo — un JSON con índice en memoria alcanza de
// sobra y no agrega ese riesgo de build.
//
// Retención: 90 días o 5000 entradas (lo que se cumpla primero), igual que
// pedía el spec original — evita que el archivo crezca sin límite en un
// proceso de fondo que puede correr meses sin reiniciarse.

const Store = require('electron-store');
const crypto = require('crypto');
const clave = require('./clave');
const log = require('./logger');

// Cifrados igual que el resto — printStore ya solo guarda un hash (no el
// HTML), pero pairingStore sí tiene IPs y user-agent reales.
//
// Perezosos y con nombre '-v2' por el mismo motivo que config.js: la clave la
// da el sistema operativo y eso exige que Electron esté listo, y los archivos
// viejos quedaron cifrados con la clave que estaba en el código (ver clave.js).
function almacen(nombre) {
  let ref = null;
  return {
    get: (k, d) => (ref ||= new Store({ name: nombre, encryptionKey: clave.resolver() })).get(k, d),
    set: (k, v) => (ref ||= new Store({ name: nombre, encryptionKey: clave.resolver() })).set(k, v),
  };
}
const printStore = almacen('audit-print-v2');
const pairingStore = almacen('audit-pairing-v2');

const RETENTION_MS = 90 * 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 5000;

function cleanup(store, key) {
  const cutoff = Date.now() - RETENTION_MS;
  let entries = store.get(key, []);
  const before = entries.length;
  entries = entries.filter((e) => new Date(e.timestamp).getTime() >= cutoff);
  if (entries.length > MAX_ENTRIES) entries = entries.slice(entries.length - MAX_ENTRIES);
  if (entries.length !== before) store.set(key, entries);
  return entries;
}

function initAuditDb() {
  const prints = cleanup(printStore, 'entries');
  const pairings = cleanup(pairingStore, 'entries');
  log.info(`Audit log inicializado (${prints.length} impresiones, ${pairings.length} intentos de pairing en historial)`);
}

function logPrintJob({ printerName, origin, success, error, html, jobId, metadata }) {
  try {
    const entries = printStore.get('entries', []);
    const htmlSize = html ? Buffer.byteLength(html, 'utf8') : null;
    const htmlHash = html ? crypto.createHash('sha256').update(html, 'utf8').digest('hex') : null;
    entries.push({
      timestamp: new Date().toISOString(),
      printerName: printerName || null,
      origin: origin || null, // 'web' | 'extension'
      success: !!success,
      error: error || null,
      htmlHash,
      htmlSize,
      jobId: jobId || null,
      metadata: metadata || null,
    });
    // Cap en escritura (no esperar al próximo arranque) — un atacante
    // spammeando /print con el rate limiter activo igual no debería poder
    // hacer crecer el archivo sin límite entre arranques.
    printStore.set('entries', entries.length > MAX_ENTRIES ? entries.slice(entries.length - MAX_ENTRIES) : entries);
  } catch (err) {
    log.error('Error escribiendo audit log de impresión:', err);
  }
}

function logPairingAttempt({ ip, success, error, userAgent }) {
  try {
    const entries = pairingStore.get('entries', []);
    entries.push({
      timestamp: new Date().toISOString(),
      ip: ip || null,
      success: !!success,
      error: error || null,
      userAgent: userAgent || null,
    });
    pairingStore.set('entries', entries.length > MAX_ENTRIES ? entries.slice(entries.length - MAX_ENTRIES) : entries);
  } catch (err) {
    log.error('Error escribiendo audit log de pairing:', err);
  }
}

function filterByRange(entries, from, to) {
  return entries.filter((e) => {
    const t = e.timestamp;
    if (from && t < from) return false;
    if (to && t > to) return false;
    return true;
  });
}

function getPrintAuditLogs({ from, to, limit = 100, offset = 0, printerName, failedOnly } = {}) {
  let entries = printStore.get('entries', []);
  entries = filterByRange(entries, from, to);
  if (printerName) entries = entries.filter((e) => e.printerName === printerName);
  if (failedOnly) entries = entries.filter((e) => !e.success);
  entries = entries.slice().reverse(); // más reciente primero
  return {
    total: entries.length,
    logs: entries.slice(offset, offset + limit),
  };
}

function getPairingAuditLogs({ from, to, limit = 100 } = {}) {
  let entries = pairingStore.get('entries', []);
  entries = filterByRange(entries, from, to);
  return entries.slice().reverse().slice(0, limit);
}

function getAuditStats({ from, to } = {}) {
  const entries = filterByRange(printStore.get('entries', []), from, to);
  const success = entries.filter((e) => e.success).length;
  const byPrinter = {};
  for (const e of entries) {
    const key = e.printerName || '(sin nombre)';
    if (!byPrinter[key]) byPrinter[key] = { printerName: key, count: 0, successCount: 0 };
    byPrinter[key].count++;
    if (e.success) byPrinter[key].successCount++;
  }
  return {
    total: entries.length,
    success,
    failed: entries.length - success,
    byPrinter: Object.values(byPrinter).sort((a, b) => b.count - a.count).slice(0, 10),
  };
}

module.exports = {
  initAuditDb,
  logPrintJob,
  logPairingAttempt,
  getPrintAuditLogs,
  getPairingAuditLogs,
  getAuditStats,
};
