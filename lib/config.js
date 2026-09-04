// TuResto Print Agent - lib/config.js
//
// Persistencia de configuración usando electron-store. Acá vive el token
// vinculado (no hardcoded), ajustes del agente, y la allowlist de orígenes
// permitidos (web + extensión de Chrome).

const Store = require('electron-store');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const clave = require('./clave');
const log = require('./logger');

// Encriptación en disco (AES-256-CBC, vía electron-store): sin esto el token
// de 256 bits (acceso completo a imprimir) y el resto de la config vivirían
// en JSON plano en %APPDATA% — cualquiera con acceso al archivo (otro usuario
// de la PC, un malware, un pendrive) lo leería directo, sin siquiera pasar
// por el agente.
//
// La clave NO está en el código: se genera una por instalación y la protege
// el sistema operativo. El porqué completo está en clave.js — resumido, una
// clave escrita acá sería pública apenas se publica el repo.

// El token de pairing antes no expiraba nunca: si alguien copiaba el
// localStorage de un navegador vinculado, tenía acceso permanente al agente
// hasta que el usuario notara algo raro (papel/tóner gastándose solo). 30
// días fuerza una re-vinculación periódica sin ser tan corto como para
// molestar en el uso normal (el front se refresca solo antes de vencer, ver
// /auth/refresh en server.js).
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// 9100 es el puerto estándar de impresión raw/JetDirect (AppSocket) — justo
// el tipo de PC donde corre este agente suele tener spoolers/drivers de
// impresora que ya lo usan. Puerto alto y no estándar para evitar el choque.
const DEFAULT_PORT = 47823;

// Si el puerto preferido está ocupado (otra instancia zombie del agente, o
// cualquier otro programa de la PC), antes el servidor simplemente no
// levantaba y el agente quedaba corriendo sin escuchar nada — invisible para
// TuResto y sin ninguna forma de que el usuario se entere. Con esta lista
// prueba el siguiente hasta encontrar uno libre; la web los sondea a todos
// (ver PUERTOS en src/pages/pos/printAgent.js — las dos listas TIENEN que
// coincidir). Todos en el rango alto/privado y sin uso conocido: no chocan
// con spoolers de impresora ni con servicios estándar.
const PUERTOS_CANDIDATOS = [47823, 47824, 47825, 51823, 55823];

// Nombre nuevo ('-v2') a propósito: los archivos viejos estaban cifrados con
// la clave que estaba escrita en el código, que ahora es pública. No se
// migran — se BORRAN (ver limpiarAlmacenesViejos): migrarlos obligaría a
// dejar esa clave en el repo, que es justo lo que se vino a sacar. El costo
// es que cada agente instalado pide vincularse una vez más, con el código de
// 6 dígitos de siempre.
const NOMBRE_ALMACEN = 'config-v2';

// Perezoso: `new Store` necesita la clave, la clave necesita safeStorage, y
// safeStorage necesita que Electron esté listo. Este módulo se requiere en el
// tope de main.js, mucho antes de app.whenReady() — crear el almacén acá
// reventaría. El primer acceso real siempre ocurre con la app ya arrancada.
let _store = null;
function store() {
  if (_store) return _store;
  _store = new Store({
    name: NOMBRE_ALMACEN,
    encryptionKey: clave.resolver(),
    defaults: {
      port: DEFAULT_PORT,
      autoStart: true,
      pairedToken: null,        // Token generado al hacer pairing
      pairedAt: null,           // ISO date del último pairing
      machineName: require('os').hostname(),
      maxRetries: 3,
      retryDelayMs: 2000,
      printTimeoutMs: 30000,
    },
  });
  return _store;
}

/**
 * Borra los almacenes de versiones anteriores del agente.
 *
 * POR QUÉ BORRAR Y NO DEJARLOS. Estaban cifrados con una clave que vivía en
 * el código y hoy es pública. Dejarlos ahí sería dejar el token de impresión
 * y el historial de tickets de ese local legibles por cualquiera que sepa
 * mirar. No se migran por el mismo motivo: migrar exigiría conservar la clave
 * vieja en el repo.
 */
function limpiarAlmacenesViejos() {
  const viejos = ['config.json', 'print-queue.json', 'audit-print.json', 'audit-pairing.json'];
  for (const nombre of viejos) {
    try {
      const ruta = path.join(require('electron').app.getPath('userData'), nombre);
      if (fs.existsSync(ruta)) {
        fs.unlinkSync(ruta);
        log.info(`Almacén de una versión anterior borrado: ${nombre}`);
      }
    } catch (err) {
      // Que no se pueda borrar uno no puede frenar el arranque.
      log.warn(`No se pudo borrar el almacén viejo ${nombre}: ${err.message}`);
    }
  }
}

// IDs de extensión de Chrome permitidos. print-extension/manifest.json tiene
// un "key" fijo (RSA pública) — con eso Chrome calcula SIEMPRE el mismo ID,
// sin importar en qué PC ni en qué carpeta se cargue la extensión sin
// publicar. Este ID no cambia con reinstalaciones ni con la ruta de destino.
const ALLOWED_EXTENSION_IDS = ['inkfndpefjkgfdmgedpncdboceaolbid'];

const ALLOWED_WEB_ORIGINS = [
  'https://turesto.pro',
  'http://localhost:3000',
  'http://localhost:5173',
];

// Migración: instalaciones previas persistieron el puerto viejo (9100) en
// electron-store. Cambiar el default en código no alcanza — el valor ya
// escrito en disco gana. Si sigue en 9100, lo pisamos una vez al arrancar.
if (store().get('port') === 9100) store().set('port', DEFAULT_PORT);

module.exports = {
  get: (key, defaultValue) => store().get(key, defaultValue),
  set: (key, value) => store().set(key, value),
  delete: (key) => store().delete(key),

  isAllowedOrigin(origin) {
    if (!origin) return false;
    if (ALLOWED_WEB_ORIGINS.includes(origin)) return true;
    for (const id of ALLOWED_EXTENSION_IDS) {
      if (origin === `chrome-extension://${id}`) return true;
    }
    // En desarrollo (extensión cargada sin publicar), permitir cualquier ID.
    if (process.env.NODE_ENV === 'development' && origin.startsWith('chrome-extension://')) {
      return true;
    }
    return false;
  },

  /** Genera un token nuevo de 256 bits al completar el pairing y lo persiste. */
  generateAndSaveToken() {
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + TOKEN_TTL_MS;
    store().set('pairedToken', token);
    store().set('pairedAt', new Date().toISOString());
    store().set('tokenExpiresAt', expiresAt);
    log.info(`Token generado, expira el ${new Date(expiresAt).toISOString()}`);
    return token;
  },

  /** null si no hay token, si venció, o si es un token viejo sin expiración
   *  registrada (instalaciones previas a este fix — ver migrateOldToken). */
  getPairedToken() {
    const token = store().get('pairedToken');
    const expiresAt = store().get('tokenExpiresAt');
    if (!token) return null;
    if (expiresAt && Date.now() > expiresAt) {
      log.warn('Token de pairing expirado, requiere re-vinculación.');
      this.unpair();
      return null;
    }
    return token;
  },

  getTokenExpiresAt() {
    return store().get('tokenExpiresAt', null);
  },

  isTokenExpired() {
    const expiresAt = store().get('tokenExpiresAt');
    const token = store().get('pairedToken');
    if (!token) return true;
    if (!expiresAt) return false; // migrado todavía no corrió: tratarlo como vigente
    return Date.now() > expiresAt;
  },

  /** Extiende el token ACTUAL (mismo valor) 30 días más — no genera uno
   *  nuevo: el front sigue usando el mismo Bearer que ya tenía guardado, solo
   *  se renueva la fecha de corte. Requiere estar autenticado (ver
   *  POST /auth/refresh en server.js, protegido por authMiddleware). */
  refreshToken() {
    const token = store().get('pairedToken');
    if (!token) throw new Error('No hay token vinculado para refrescar');
    const expiresAt = Date.now() + TOKEN_TTL_MS;
    store().set('tokenExpiresAt', expiresAt);
    log.info(`Token refrescado, nuevo vencimiento ${new Date(expiresAt).toISOString()}`);
    return { token, expiresAt };
  },

  /** Installs de antes de este fix tienen pairedToken sin tokenExpiresAt —
   *  sin esto, getPairedToken() los trataría como "sin expiración nunca" (el
   *  branch `!expiresAt` de arriba) para siempre. Correr una vez al arrancar
   *  les da 30 días desde AHORA, no desde que se vincularon hace quién sabe
   *  cuánto. */
  migrateOldToken() {
    const token = store().get('pairedToken');
    const expiresAt = store().get('tokenExpiresAt');
    if (token && !expiresAt) {
      store().set('tokenExpiresAt', Date.now() + TOKEN_TTL_MS);
      log.info('Token de una instalación previa migrado: vence en 30 días desde ahora.');
    }
  },

  unpair() {
    store().delete('pairedToken');
    store().delete('pairedAt');
    store().delete('tokenExpiresAt');
  },

  TOKEN_TTL_MS,
  limpiarAlmacenesViejos,
  PUERTOS_CANDIDATOS,
  DEFAULT_PORT,
};
