// TuResto Print Agent - main.js
//
// Entry point Electron. A pedido explícito: el agente no tiene NINGUNA UI
// visible — ni bandeja, ni ventana, ni panel de configuración. Es un
// proceso de fondo puro:
//  - Single instance lock (no se puede abrir dos veces)
//  - Auto-start on boot (siempre activado, no hay UI para destildarlo)
//  - Arranque del servidor Express local + cola persistente
//  - Auto-pairing vía protocolo turesto:// (ver handlePairUrl): la pestaña
//    que lo dispara se actualiza sola via polling a /pair/claim — no hace
//    falta abrir ni redirigir ningún navegador.
//  - Para cerrarlo sin Administrador de tareas: POST /quit (ver lib/server.js)

const { app, Notification } = require('electron');
const log = require('./lib/logger');
const config = require('./lib/config');
const pairing = require('./lib/pairing');
const { startServer } = require('./lib/server');
const { initQueue } = require('./lib/queue');
const { initAuditDb } = require('./lib/audit');

const VERSION = require('./package.json').version;

// ── Single instance lock ─────────────────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  log.info('Otra instancia del agente ya está corriendo. Cerrando.');
  app.quit();
  process.exit(0);
}

// Registra el protocolo turesto:// — en Windows el instalador NSIS ya lo deja
// en el registry (ver "protocols" en package.json), pero llamarlo también
// acá es necesario en dev (npm start, sin instalar) y no rompe nada en prod.
app.setAsDefaultProtocolClient('turesto');

// Una sola URL turesto:// puede venir en cualquiera de estos argv (Windows
// pasa la línea de comando completa, no solo la URL).
function extraerUrlTuResto(argv) {
  return (argv || []).find((a) => a.startsWith('turesto://'));
}

// Si el agente YA está corriendo y el usuario clickea turesto:// de nuevo,
// Windows lanza una "segunda instancia" que pierde el lock — eso dispara
// este evento EN LA INSTANCIA ORIGINAL, con la URL en argv.
app.on('second-instance', (_event, argv) => {
  const url = extraerUrlTuResto(argv);
  if (url) handlePairUrl(url);
});

// macOS: el SO entrega la URL directo, no por argv.
app.on('open-url', (event, url) => { event.preventDefault(); handlePairUrl(url); });

function setupAutoStart() {
  app.setLoginItemSettings({ openAtLogin: true, path: app.getPath('exe'), args: ['--hidden'] });
}

// ── Auto-pairing (turesto://pair) ─────────────────────────────────────────
// Genera el token igual que el flujo manual (POST /pair/verify), pero sin
// mostrar ni pedir el código de 6 dígitos. El token queda en memoria
// (pairing.setPendingAutoPair) — la pestaña que disparó turesto://pair lo
// reclama sola vía GET /pair/claim (polling, ver printAgent.js). No hace
// falta abrir/redirigir ningún navegador ni pasar nada por la URL.
function handlePairUrl(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { log.warn(`turesto:// inválida: ${rawUrl}`); return; }
  if (parsed.protocol !== 'turesto:') return;
  const accion = parsed.hostname || parsed.pathname.replace(/^\/+/, '');
  if (accion !== 'pair') { log.warn(`turesto:// acción desconocida: ${accion}`); return; }

  const token = config.generateAndSaveToken();
  pairing.invalidateCode();
  pairing.setPendingAutoPair(token, config.get('machineName'));
  log.info('Auto-pairing completado, esperando que el navegador lo reclame.');
}

// ── App lifecycle ─────────────────────────────────────────────────────────
app.whenReady().then(() => {
  log.info(`Iniciando TuResto Print Agent v${VERSION}`);

  setupAutoStart();
  // Antes que nada: los almacenes de versiones anteriores quedaron cifrados
  // con una clave que vivía en el código y hoy es pública (el repo del agente
  // es abierto). Se borran para que no queden legibles. Ver lib/clave.js.
  config.limpiarAlmacenesViejos();
  initQueue();
  initAuditDb();
  // Instalaciones previas a la expiración de tokens (Fix 5) tienen un
  // pairedToken sin tokenExpiresAt — sin migrarlo quedaría "vigente para
  // siempre" en vez de arrancar su cuenta regresiva de 30 días ahora.
  config.migrateOldToken();

  startServer()
    .then(() => log.info('Servidor HTTP iniciado correctamente'))
    .catch((err) => {
      // Bug real (2026-08-19): sin esto, si el puerto ya estaba ocupado (otra
      // instancia vieja que no cerró bien, u otro programa), el error quedaba
      // SOLO en el log — el proceso Electron seguía vivo en el Administrador
      // de tareas para siempre, sin escuchar nada, indistinguible a simple
      // vista de un agente que anda bien. Sin tray ni ventana (rediseño a
      // pedido explícito) esta notificación nativa es la única forma de
      // avisar que algo está mal sin reconstruir esa UI.
      log.error('Error iniciando servidor HTTP:', err);
      if (Notification.isSupported()) {
        new Notification({
          title: 'TuResto Impresión — no pudo iniciar',
          body: err.code === 'EADDRINUSE'
            ? 'El puerto ya está en uso (¿otra instancia del agente corriendo?). Cerrá el proceso desde el Administrador de tareas y reabrí el agente.'
            : `No se pudo iniciar el servidor local: ${err.message}`,
        }).show();
      }
    });

  // Si Windows lanzó esta instancia directo con turesto://pair (el agente
  // no estaba corriendo todavía), resolverlo apenas el server esté arriba.
  const urlInicial = extraerUrlTuResto(process.argv);
  if (urlInicial) handlePairUrl(urlInicial);

  // Sin ventanas nunca, 'window-all-closed' no debería disparar jamás — pero
  // si algo creara una en el futuro, que no mate el proceso de fondo.
  app.on('window-all-closed', (e) => e.preventDefault());
});

app.on('before-quit', () => log.info('Apagando agente...'));
