// TuResto Print Agent - lib/pairing.js
//
// Pairing por código de 6 dígitos.
//
//  1. El agente genera un código aleatorio al arrancar (o a pedido).
//  2. Lo muestra en su ventana de pairing.
//  3. El usuario lo ingresa en TuResto (Ajustes › Impresoras).
//  4. La web llama POST /pair/verify con el código.
//  5. Si coincide, el agente genera un token real (256 bits) y lo devuelve.
//     La web lo guarda en localStorage; de ahí en más manda
//     `Authorization: Bearer <token>` en cada request.
//
// El código de 6 dígitos expira a los 10 minutos por seguridad.
//
// Lockout: el rate limit de /pair/verify (5/min, ver rateLimiter.js) por sí
// solo deja ~7200 intentos/día — alcanza para fuerza bruta de un código de 6
// dígitos (1 millón de combinaciones) en 1-2 días. El lockout agrega un
// segundo freno: 5 fallos → 15 min bloqueado, sin importar la IP de origen
// (el código es el secreto compartido, no la IP).

const crypto = require('crypto');
const config = require('./config');
const log = require('./logger');

let currentCode = null;
let codeGeneratedAt = null;
const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_LENGTH = 6;

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;
const FAILED_ATTEMPTS_RESET_MS = 30 * 60 * 1000; // sin fallos por 30 min → contador vuelve a 0

function generateCode() {
  let code = '';
  for (let i = 0; i < CODE_LENGTH; i++) {
    // randomInt y no `randomBytes[i] % 10`: un byte va de 0 a 255, y 256 no es
    // múltiplo de 10, así que con el módulo los dígitos 0-5 salían 26 veces
    // cada 256 y los 6-9 solo 25. El sesgo es chico y con el bloqueo a los 5
    // intentos no cambia nada en la práctica — se corrige porque es una línea y
    // porque un generador de códigos de seguridad no debería tener sesgo.
    code += crypto.randomInt(0, 10).toString();
  }
  currentCode = code;
  codeGeneratedAt = Date.now();
  log.info(`Nuevo código de pairing generado (expira en 10 min).`);
  return code;
}

function getCurrentCode() {
  if (!currentCode || !codeGeneratedAt || (Date.now() - codeGeneratedAt) > CODE_TTL_MS) {
    generateCode();
  }
  return currentCode;
}

function getCodeRemainingMs() {
  if (!codeGeneratedAt) return CODE_TTL_MS;
  return Math.max(0, CODE_TTL_MS - (Date.now() - codeGeneratedAt));
}

function isCodeValid(code) {
  if (!currentCode || !codeGeneratedAt) return false;
  if ((Date.now() - codeGeneratedAt) > CODE_TTL_MS) return false;

  // Se comparan BYTES, no caracteres. El guard anterior miraba `code.length`,
  // que en JavaScript cuenta caracteres: "áéíóúñ" tiene largo 6 igual que
  // "123456", pero ocupa 12 bytes. Pasaba el guard y timingSafeEqual —que exige
  // buffers del MISMO largo en bytes— tiraba RangeError. Ese error no lo
  // atrapaba nadie (ni verifyAndPair ni el handler de /pair/verify), así que
  // escribir seis acentos en la casilla del código rompía el pedido con un 500
  // en vez de contestar "código incorrecto", y encima ni siquiera contaba el
  // intento fallido.
  const ingresado = Buffer.from(code, 'utf8');
  const esperado = Buffer.from(currentCode, 'utf8');
  if (ingresado.length !== esperado.length) return false;

  // Comparación en tiempo constante para evitar timing attacks.
  return crypto.timingSafeEqual(ingresado, esperado);
}

function invalidateCode() {
  currentCode = null;
  codeGeneratedAt = null;
}

// ── Lockout ────────────────────────────────────────────────────────────────
// Persistido en electron-store (config.js) para que sobreviva un reinicio
// del agente — un atacante no puede "resetear" su bloqueo apagando/prendiendo
// el proceso (ej. vía /quit, que no requiere auth).

function getLockoutState() {
  return {
    failedAttempts: config.get('pairing.failedAttempts', 0),
    lockedUntil: config.get('pairing.lockedUntil', 0),
    lastFailedAt: config.get('pairing.lastFailedAt', 0),
  };
}

function setLockoutState(state) {
  config.set('pairing.failedAttempts', state.failedAttempts);
  config.set('pairing.lockedUntil', state.lockedUntil);
  config.set('pairing.lastFailedAt', state.lastFailedAt);
}

function isLocked() {
  return Date.now() < getLockoutState().lockedUntil;
}

function getLockoutRemainingMs() {
  return Math.max(0, getLockoutState().lockedUntil - Date.now());
}

function registerFailedAttempt() {
  const state = getLockoutState();
  const now = Date.now();

  if (state.lastFailedAt && now - state.lastFailedAt > FAILED_ATTEMPTS_RESET_MS) {
    state.failedAttempts = 0;
  }

  state.failedAttempts++;
  state.lastFailedAt = now;

  let justLocked = false;
  if (state.failedAttempts >= MAX_FAILED_ATTEMPTS) {
    state.lockedUntil = now + LOCKOUT_DURATION_MS;
    state.failedAttempts = 0;
    justLocked = true;
    log.warn(`Pairing bloqueado por ${LOCKOUT_DURATION_MS / 60000} min (demasiados intentos fallidos)`);
  } else {
    log.warn(`Intento de pairing fallido (${state.failedAttempts}/${MAX_FAILED_ATTEMPTS})`);
  }

  setLockoutState(state);
  return { ...state, justLocked };
}

function resetLockout() {
  setLockoutState({ failedAttempts: 0, lockedUntil: 0, lastFailedAt: 0 });
}

// ── Auto-pairing (turesto://) ─────────────────────────────────────────────
// El agente no tiene ventana ni bandeja: cuando completa el auto-pairing
// (ver main.js → handlePairUrl), no hay forma de "mostrarle" el token al
// navegador — lo deja acá, en memoria, por un rato corto. La MISMA pestaña
// que disparó turesto://pair lo va a pedir solita por /pair/claim (polling),
// así nunca hace falta abrir/redirigir ninguna ventana.
let pendingAutoPair = null; // { token, machine, expiresAt }
const AUTOPAIR_CLAIM_TTL_MS = 60 * 1000;

function setPendingAutoPair(token, machine) {
  pendingAutoPair = { token, machine, expiresAt: Date.now() + AUTOPAIR_CLAIM_TTL_MS };
}

/** Un solo uso: la primera pestaña que pregunta se lo lleva, evita que dos
 *  polls concurrentes (o una recarga) reclamen el mismo token dos veces. */
function claimPendingAutoPair() {
  if (!pendingAutoPair || Date.now() > pendingAutoPair.expiresAt) {
    pendingAutoPair = null;
    return null;
  }
  const claim = pendingAutoPair;
  pendingAutoPair = null;
  return claim;
}

/**
 * @param {string} code - Código de 6 dígitos ingresado por el usuario.
 * @returns {{ success: boolean, token?: string, error?: string }}
 */
function verifyAndPair(code) {
  if (isLocked()) {
    const remainingMin = Math.ceil(getLockoutRemainingMs() / 60000);
    log.warn(`Intento de pairing durante lockout (${remainingMin} min restantes)`);
    return { success: false, error: `Bloqueado por seguridad. Intentá nuevamente en ${remainingMin} minuto(s).` };
  }

  if (!code || typeof code !== 'string') {
    return { success: false, error: 'Código inválido' };
  }
  const sanitized = code.trim().replace(/\s/g, '');
  if (!isCodeValid(sanitized)) {
    const state = registerFailedAttempt();
    if (state.justLocked) {
      return { success: false, error: 'Demasiados intentos fallidos. Bloqueado por 15 minutos.' };
    }
    const remaining = MAX_FAILED_ATTEMPTS - state.failedAttempts;
    log.warn('Intento de pairing con código inválido o vencido.');
    return { success: false, error: `Código incorrecto o vencido. ${remaining} intento(s) restante(s).` };
  }

  const token = config.generateAndSaveToken();
  invalidateCode();
  resetLockout();
  log.info('Pairing exitoso. Token generado y guardado.');
  return { success: true, token };
}

module.exports = {
  getCurrentCode,
  getCodeRemainingMs,
  generateCode,
  verifyAndPair,
  invalidateCode,
  setPendingAutoPair,
  claimPendingAutoPair,
  isLocked,
  getLockoutRemainingMs,
};
