// TuResto Print Agent - lib/logger.js
//
// Wrapper sobre electron-log. Escribe a archivo rotativo + consola.
// Archivo: %APPDATA%/turesto-agente-impresion/logs/main.log

const log = require('electron-log');

log.transports.file.level = 'info';
log.transports.file.maxSize = 5 * 1024 * 1024; // 5MB
log.transports.file.format = '[{y}-{m}-{d} {h}:{i}:{s}.{ms}] [{level}] {text}';

log.transports.console.level = 'debug';
log.transports.console.format = '[{h}:{i}:{s}] [{level}] {text}';

// En producción no hay consola visible — no tiene sentido escribir ahí.
if (process.env.NODE_ENV !== 'development' && !process.argv.includes('--dev')) {
  log.transports.console.level = false;
}

module.exports = log;
