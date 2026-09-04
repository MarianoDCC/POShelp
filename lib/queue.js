// TuResto Print Agent - lib/queue.js
//
// Cola de impresión persistente con reintentos.
//
// POR QUÉ no usa pdf-to-printer/SumatraPDF (como la v1 empaquetada con pkg):
// Electron YA trae un Chromium completo. webContents.print({ silent: true,
// deviceName }) imprime directo a una impresora del sistema sin diálogo,
// sin depender de un binario externo ni de detectar Edge/Chrome instalado.
// Una sola ventana oculta, reutilizada, hace de "motor de impresión".
//
// Características:
//  - Persiste los jobs en disco (electron-store) para sobrevivir reinicios.
//  - Procesa jobs secuencialmente (uno a la vez) para no saturar la impresora.
//  - Reintenta hasta N veces con backoff exponencial.
//  - Si la impresora no responde en T segundos, marca el job como fallido.

const { BrowserWindow } = require('electron');
const { EventEmitter } = require('events');
const Store = require('electron-store');
// crypto.randomUUID() nativo de Node (>=14.17) en vez del paquete `uuid`:
// mismo resultado, sin depender de un tercero (auditoría de seguridad —
// la versión que estaba trae un CVE moderado en v3/v5/v6, que acá ni se
// usaba, pero total no hace falta la dependencia para nada).
const { randomUUID: uuidv4 } = require('crypto');
const config = require('./config');
const log = require('./logger');

// encryptionKey: la cola guarda el HTML crudo de cada ticket/comanda/arqueo
// (nombres de clientes, montos, medios de pago) — el store más sensible de
// los tres, sin esto quedaba en texto plano en disco (ver mismo comentario
// en config.js).
// Perezoso y '-v2': ver clave.js y config.js — la clave la da el SO y hace
// falta que Electron esté listo, cosa que no pasa al cargar este módulo.
let _queueStore = null;
function queueStore() {
  if (!_queueStore) _queueStore = new Store({ name: 'print-queue-v2', encryptionKey: require('./clave').resolver() });
  return _queueStore;
}
const emitter = new EventEmitter();

let isProcessing = false;
let printWindow = null;

// Solo se le permite salir a la red al logo del propio backend. Todo lo demás
// —incluido cualquier host de la LAN del local— se corta acá.
const HOSTS_PERMITIDOS = /(^|\.)turesto\.pro$/i;

function getPrintWindow() {
  if (printWindow && !printWindow.isDestroyed()) return printWindow;
  printWindow = new BrowserWindow({
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      // Un ticket es HTML estático: no hay un solo caso donde necesite correr
      // JavaScript. Con JS habilitado, cualquier <script> que se le escape al
      // validador de HTML se ejecutaba de verdad — es un renderer de Chromium
      // con red normal, así que podía llamar a la casa o barrer la LAN del
      // local. Apagándolo, todo ese grupo de agujeros deja de existir en vez
      // de depender de que una expresión regular no tenga huecos.
      javascript: false,
      webgl: false,
    },
  });

  // Segundo cerrojo, este a nivel de red y no de parseo de texto: el validador
  // solo mira src/href, así que no ve un background:url(...) en un style, un
  // @import adentro de un <style>, una URL sin protocolo (//host/x) ni un
  // srcset. Cualquiera de esos alcanzaba para que la ventana de impresión
  // fuera a buscar algo afuera. Filtrando el request en sí no importa por
  // dónde venga escondida la URL.
  printWindow.webContents.session.webRequest.onBeforeRequest((detalles, callback) => {
    const url = detalles.url || '';
    if (url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('about:')) {
      return callback({ cancel: false });
    }
    try {
      if (HOSTS_PERMITIDOS.test(new URL(url).hostname)) return callback({ cancel: false });
    } catch { /* URL que no parsea: se corta */ }
    log.warn(`Recurso remoto bloqueado en la ventana de impresión: ${url.slice(0, 120)}`);
    callback({ cancel: true });
  });

  printWindow.on('closed', () => { printWindow = null; });
  return printWindow;
}

async function listPrinters() {
  const win = getPrintWindow();
  return win.webContents.getPrintersAsync();
}

function getJobs() {
  return queueStore().get('jobs', []);
}

// Cuántos jobs YA TERMINADOS se conservan. Esto NO es el historial de
// impresiones: ese vive en audit.js, que guarda 90 días / 5000 entradas con
// hash y tamaño del HTML (no el HTML). Acá alcanza con los últimos para que
// GET /jobs muestre algo útil.
const MAX_JOBS_TERMINADOS = 300;

const jobTerminado = (j) => j.status === 'success' || j.status === 'failed';

/**
 * Poda la cola ANTES de escribirla en disco.
 *
 * BUG REAL QUE ARREGLA (crecimiento sin techo): nada limpiaba esta cola nunca.
 * `clearCompleted()` existe pero su único llamador es DELETE /jobs, y ese
 * endpoint no lo llama NADIE en todo el frontend (verificado). O sea que cada
 * ticket impreso quedaba guardado para siempre CON SU HTML COMPLETO, que son
 * varios KB. Y no es solo el archivo creciendo: `addJob`/`updateJob` hacen
 * read-modify-write del array ENTERO, y el store está encriptado, así que cada
 * impresión re-serializaba y re-encriptaba toda la historia — unas 4 veces por
 * ticket. Un bar con 200 tickets por día llega al año con decenas de miles de
 * jobs y cientos de MB, e imprimir pasa de instantáneo a tardar segundos.
 * Se presentaría como "el agente se puso lento con el tiempo", que es
 * justamente lo más difícil de diagnosticar.
 *
 * Dos podas, por separado:
 *  1. Al job terminado se le tira el HTML — ya no lo lee nadie (getJob y
 *     getAllJobs lo sacan igual, y un ticket NUNCA se reimprime solo, ver
 *     processJob), así que es peso muerto.
 *  2. Se conservan los últimos MAX_JOBS_TERMINADOS terminados.
 *
 * Los pendientes NO se tocan nunca, por más que sean muchos: tirar uno sería
 * perder un ticket que todavía no se imprimió. Y se respeta el orden original
 * para que processQueue siga sacando el más viejo primero.
 */
function podar(jobs) {
  const limpios = jobs.map((j) => (jobTerminado(j) && 'html' in j ? stripHtml(j) : j));
  const sobran = limpios.filter(jobTerminado).length - MAX_JOBS_TERMINADOS;
  if (sobran <= 0) return limpios;
  let tirados = 0;
  return limpios.filter((j) => {
    if (tirados < sobran && jobTerminado(j)) { tirados++; return false; }
    return true;
  });
}

function setJobs(jobs) {
  queueStore().set('jobs', podar(jobs));
}

function addJob({ html, printerName, copies = 1 }) {
  const job = {
    id: uuidv4(),
    html,
    printerName,
    copies,
    status: 'pending',
    attempts: 0,
    maxRetries: config.get('maxRetries', 3),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastError: null,
  };
  const jobs = getJobs();
  jobs.push(job);
  setJobs(jobs);
  log.info(`Job ${job.id} encolado para impresora "${printerName}"`);
  emitter.emit('job:added', job);
  processQueue();
  return job;
}

// El HTML puede pesar varios KB; no lo devolvemos en listados para no inflar
// las respuestas — solo lo necesita processJob.
function stripHtml(job) {
  const { html, ...rest } = job;
  return rest;
}

function getJob(id) {
  const j = getJobs().find((j) => j.id === id);
  return j ? stripHtml(j) : null;
}

function getAllJobs() {
  return getJobs().map(stripHtml);
}

function clearCompleted() {
  const jobs = getJobs().filter((j) => j.status !== 'success' && j.status !== 'failed');
  setJobs(jobs);
}

function updateJob(id, updates) {
  const jobs = getJobs();
  const idx = jobs.findIndex((j) => j.id === id);
  if (idx === -1) return null;
  jobs[idx] = { ...jobs[idx], ...updates, updatedAt: new Date().toISOString() };
  setJobs(jobs);
  emitter.emit('job:updated', stripHtml(jobs[idx]));
  return jobs[idx];
}

async function processQueue() {
  if (isProcessing) return;
  isProcessing = true;
  try {
    while (true) {
      const jobs = getJobs();
      // Solo 'pending': ya NO existe el estado 'retry' (ver processJob) — un
      // ticket nunca se reimprime solo, así que nunca quedan jobs en 'retry'.
      const nextJob = jobs.find((j) => j.status === 'pending');
      if (!nextJob) break;
      await processJob(nextJob);
      await sleep(200); // respiro entre jobs para no saturar la impresora
    }
  } finally {
    isProcessing = false;
  }
}

// El HTML trae <meta name="turesto-margin" content="printableArea"> cuando
// el ticket es para una impresora de OFICINA (ver printTicket.js,
// metaMargenHtml) — sin esto, ESTE archivo forzaba marginType:'none' para
// TODO, ignorando cualquier CSS del HTML (@page/padding). Ese fue el bug
// real: ninguna de las 3 correcciones de CSS en el frontend podía cambiar
// nada, porque Electron ya le pedía a Windows "sin margen" antes de mirar
// el HTML — el driver clipeaba lo que caía en su zona física no imprimible,
// sin importar qué dijera la página (reportado con foto 3 veces, 2026-07-14).
function marginTypeDe(html) {
  return /turesto-margin"\s+content="printableArea"/.test(html) ? 'printableArea' : 'none';
}

function printWith(win, deviceName, copies, marginType) {
  return new Promise((resolve, reject) => {
    win.webContents.print(
      // silent + SIN encabezado/pie: displayHeaderFooter false asegura que NO
      // se imprima la URL/título/impresora arriba o abajo del ticket
      // (reportado: "sale el nombre de la impresora abajo de la comanda").
      // marginType 'none' (térmica, edge-to-edge) o 'printableArea' (oficina,
      // respeta el área imprimible real que reporta el driver de Windows).
      { silent: true, deviceName, copies, margins: { marginType }, displayHeaderFooter: false },
      (success, failureReason) => {
        if (success) resolve();
        else reject(new Error(failureReason || 'Fallo de impresión desconocido'));
      },
    );
  });
}

/**
 * Resuelve la impresora destino UNA sola vez, ANTES de imprimir.
 *
 * POR QUÉ (bug de las 5 copias): antes se imprimía con la impresora elegida y,
 * si Windows devolvía "fallo", se reimprimía con la default. Pero
 * webContents.print devuelve success=false SEGUIDO aunque el papel YA haya
 * salido (falso negativo típico en Windows) — así cada intento sacaba 2
 * copias, y encima processJob reintentaba 4 veces con backoff (≈1 minuto).
 * Resultado real: 5 tickets de una sola cancelación. Ahora, si la impresora
 * elegida no existe, se cae a la default ANTES de mandar nada — jamás dos
 * impresiones físicas para el mismo ticket.
 */
async function resolveDevice(job) {
  if (!job.printerName) return undefined; // ya viene sin elegir → default del SO
  try {
    const printers = await listPrinters();
    if (printers.some((p) => p.name === job.printerName)) return job.printerName;
    const def = printers.find((p) => p.isDefault);
    log.warn(`Impresora "${job.printerName}" no está; uso la default "${def?.name || 'del sistema'}"`);
    return def ? def.name : undefined;
  } catch {
    return job.printerName; // no pudimos listar: intentamos con lo que hay
  }
}

async function processJob(job) {
  log.info(`Procesando job ${job.id}`);
  updateJob(job.id, { status: 'processing' });
  try {
    const win = getPrintWindow();
    await win.webContents.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(job.html)}`);
    const deviceName = await resolveDevice(job);
    const marginType = marginTypeDe(job.html);
    await withTimeout(printWith(win, deviceName, job.copies || 1, marginType), config.get('printTimeoutMs', 30000));
    updateJob(job.id, { status: 'success', lastError: null });
    log.info(`Job ${job.id} impreso`);
    return true;
  } catch (err) {
    // NUNCA reimprimir solo: un ticket de cocina duplicado confunde al cocinero
    // (peor que uno faltante, que se nota y se reimprime a mano desde el POS).
    // Como no se puede distinguir "falló de verdad" de "imprimió pero Windows
    // dijo que no", la única opción segura es NO reintentar la impresión física.
    log.error(`Job ${job.id} falló: ${err.message}`);
    updateJob(job.id, { status: 'failed', attempts: 1, lastError: err.message });
    emitter.emit('job:failed', getJob(job.id));
    return false;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`Print timeout after ${ms}ms`)), ms)),
  ]);
}

function initQueue() {
  // Precrea la ventana oculta de impresión al arrancar — crearla tarda 1-3s
  // (Electron levanta un renderer nuevo), y antes pasaba recién en el primer
  // /printers o /print, haciendo que la PRIMERA "Detectar" del usuario se
  // sintiera lenta. Precreada acá, ya está lista cuando se la pidan.
  getPrintWindow();

  // Jobs que quedaron 'processing' al cerrarse el agente → marcar FALLIDOS, no
  // reintentar: pueden haber impreso justo antes del cierre, y reimprimir
  // sacaría un duplicado (misma política anti-duplicado que processJob). Si de
  // verdad no salió, el mozo lo reimprime a mano desde el POS.
  const jobs = getJobs();
  let changed = false;
  for (const job of jobs) {
    if (job.status === 'processing' || job.status === 'retry') {
      job.status = 'failed';
      job.lastError = 'Interrumpido por reinicio del agente';
      changed = true;
    }
  }
  if (changed) log.info('Jobs interrumpidos marcados como fallidos (no se reimprimen solos)');
  // Se escribe SIEMPRE, haya cambiado algo o no: los agentes que vienen de una
  // versión anterior arrastran una cola sin podar nunca (ver podar()), y si
  // solo se guardara cuando hay jobs interrumpidos esa cola vieja se quedaría
  // gigante hasta la próxima vez que justo se corte una impresión. Escribir
  // acá la poda una vez al arrancar y listo.
  const antes = jobs.length;
  setJobs(jobs);
  const despues = getJobs().length;
  if (despues < antes) log.info(`Cola podada al arrancar: ${antes} → ${despues} jobs.`);

  setTimeout(() => processQueue(), 1000);
}

module.exports = {
  initQueue,
  addJob,
  getJob,
  getAllJobs,
  clearCompleted,
  listPrinters,
  on: emitter.on.bind(emitter),
  off: emitter.off.bind(emitter),
};
