// TuResto Print Agent - lib/clave.js
//
// La clave con la que se cifran los almacenes en disco (config, cola de
// impresión, auditoría).
//
// POR QUÉ EXISTE ESTE ARCHIVO. Antes la clave era una constante escrita en
// `config.js`, la misma para todas las instalaciones del mundo. Eso alcanzaba
// mientras el código era privado: para sacarla había que decompilar el .asar.
// Con el código publicado deja de servir — una clave en un repo público es una
// clave que cualquiera lee, y con ella se abre el archivo de cualquier PC que
// tenga el agente instalado (adentro está el token de impresión y el historial
// de tickets).
//
// CÓMO SE RESUELVE AHORA. Se genera una clave al azar POR INSTALACIÓN y se
// guarda protegida por el sistema operativo (`safeStorage` de Electron: DPAPI
// en Windows, Keychain en macOS, el llavero de escritorio en Linux). Tres
// cosas mejoran de golpe:
//
//   1. No viaja en el código. Publicar el repo no expone nada.
//   2. No se comparte entre instalaciones: romper una no ayuda con las demás.
//   3. La protege el SO, atada al usuario de Windows — copiar el archivo a
//      otra PC no sirve, allá no se puede desencriptar.
//
// SI EL SO NO PUEDE (Linux sin llavero, por ejemplo) se cae a guardar la clave
// en un archivo con permisos restringidos. Es más débil que el llavero, pero
// sigue siendo por instalación y al azar: el repo público no la revela igual.
// Un atacante con acceso local a esa PC gana en los dos casos — y si tiene
// acceso local ya ganó de todos modos.

const { app, safeStorage } = require('electron');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const log = require('./logger');

const ARCHIVO = 'clave-almacen.bin';

// Memoizada: resolverla implica leer un archivo y hablar con el SO, y la
// piden cuatro almacenes distintos en cada arranque.
let cache = null;

function ruta() {
  return path.join(app.getPath('userData'), ARCHIVO);
}

/** true si el SO tiene un llavero utilizable (en Linux puede no haberlo). */
function hayLlavero() {
  try {
    return safeStorage.isEncryptionAvailable();
  } catch {
    return false;
  }
}

function generar() {
  return crypto.randomBytes(32).toString('hex');
}

function guardar(clave, destino) {
  try {
    if (hayLlavero()) {
      fs.writeFileSync(destino, safeStorage.encryptString(clave), { mode: 0o600 });
    } else {
      // Sin llavero: al menos que no sea legible por otros usuarios de la PC.
      // El prefijo distingue los dos formatos al leer.
      fs.writeFileSync(destino, `plano:${clave}`, { encoding: 'utf8', mode: 0o600 });
    }
  } catch (err) {
    // Que no se pueda persistir no puede tumbar el agente: sigue con la clave
    // en memoria y el próximo arranque genera otra. Se pierde lo guardado
    // (hay que re-vincular), pero el bar puede imprimir HOY, que es lo que
    // importa. Queda en el log para poder diagnosticarlo.
    log.error(`No se pudo guardar la clave de los almacenes: ${err.message}`);
  }
}

function leer(origen) {
  const bruto = fs.readFileSync(origen);
  const comoTexto = bruto.toString('utf8');
  if (comoTexto.startsWith('plano:')) return comoTexto.slice('plano:'.length);
  return safeStorage.decryptString(bruto);
}

/**
 * La clave de esta instalación. La primera vez la genera y la guarda; después
 * la devuelve siempre igual.
 *
 * OJO CON EL MOMENTO: `safeStorage` exige que Electron esté listo, así que
 * esto NO se puede llamar al cargar el módulo — por eso los almacenes que la
 * usan se crean de forma perezosa, en el primer acceso real (ya con la app
 * arrancada), y no en el `require`.
 */
function resolver() {
  if (cache) return cache;

  const destino = ruta();
  if (fs.existsSync(destino)) {
    try {
      cache = leer(destino);
      return cache;
    } catch (err) {
      // Clave ilegible (llavero del SO reseteado, perfil de Windows nuevo,
      // archivo corrupto). Se regenera: lo guardado con la anterior queda
      // inaccesible y el agente va a pedir vincularse de nuevo, que es
      // molesto pero recuperable — quedarse sin arrancar no lo es.
      log.error(`Clave de los almacenes ilegible, se genera una nueva: ${err.message}`);
    }
  }

  cache = generar();
  guardar(cache, destino);
  log.info(`Clave de los almacenes generada${hayLlavero() ? ' y protegida por el sistema operativo' : ' (sin llavero del SO: archivo restringido)'}.`);
  return cache;
}

module.exports = { resolver };
