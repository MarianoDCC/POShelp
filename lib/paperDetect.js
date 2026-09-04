// TuResto Print Agent - lib/paperDetect.js
//
// Detección best-effort del ancho de rollo térmico de una impresora ya
// instalada en Windows. Auditado con Fable (2026-07-12) junto con el mismo
// problema del lado web (printTicket.js: fallback a 58MM + wrap defensivo).
//
// POR QUÉ acá y no en la web: el navegador no tiene NINGUNA API para
// consultar el tamaño de papel real de una impresora — la única fuente de
// esa info es el propio driver de Windows, y a eso solo llega el agente
// nativo (corre en la PC del local). Electron tampoco expone esto en
// getPrintersAsync() (confirmado empíricamente: su .options solo trae
// printer-location/make-and-model/driverinfo, nunca paper size) — hace
// falta PowerShell/WMI, que sí lo tiene.
//
// Esto es un ASISTENTE, no una autoridad: un driver Genérico/Texto o una
// impresora compartida mal configurada puede reportar A4 aunque el rollo
// real sea térmico — la misma mentira que causó el bug original (ver
// printTicket.js). Por eso esto solo alimenta un botón "Detectar
// automáticamente" que el dueño confirma, nunca pisa el selector manual solo.

const { execFile } = require('child_process');
const log = require('./logger');

const PS_PATH = process.env.SystemRoot
  ? `${process.env.SystemRoot}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`
  : 'powershell.exe';

// Get-PrintConfiguration puede colgarse largo rato con una impresora de red
// caída — nunca puede trabar un /printer-config y de rebote la detección.
const PS_TIMEOUT_MS = 8000;

function runPowerShell(command) {
  return new Promise((resolve, reject) => {
    execFile(
      PS_PATH,
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command],
      { timeout: PS_TIMEOUT_MS, windowsHide: true },
      (err, stdout) => {
        if (err) return reject(err);
        resolve(stdout);
      },
    );
  });
}

// Ancho en mm -> el mismo código que ya usa la web (ANCHO_MM en printTicket.js).
// 57/58/60mm = rollo angosto; 72/76/80/82/83mm = rollo estándar (72 importa:
// Star y varios genéricos reportan el ancho IMPRIMIBLE, no el físico, de un
// rollo de 80mm real).
const ANCHOS_58 = [57, 58, 60];
const ANCHOS_80 = [72, 76, 80, 82, 83];
// Par de dimensiones ("80mm x 297mm", "80 x 3276") — la señal más confiable,
// porque un ancho de página real casi siempre viene con el largo al lado.
const RE_MM_PAR = /(\d{2,3})(?:\.\d+)?\s*(?:mm)?\s*[x×(]/gi;
// Bug real (reportado 2026-08-04, "me manda una comanda chica no del tamaño
// de mi impresora"): muchos drivers térmicos (sobre todo genéricos/Bixolon/
// Xprinter) nombran el papel custom SOLO como "80mm" o "80 mm Bond", sin
// ningún "x ancho" al lado — RE_MM_PAR nunca matcheaba esos, la detección
// caía siempre al fallback de 58mm (ver printTicket.js) aunque la impresora
// fuera de 80mm real. Fallback: mismo número pero con "mm" pegado, solo.
const RE_MM_SOLO = /(\d{2,3})(?:\.\d+)?\s*mm\b/gi;

function anchoDesdeTexto(texto) {
  if (!texto) return null;
  for (const re of [RE_MM_PAR, RE_MM_SOLO]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(texto))) {
      const n = Number(m[1]);
      if (ANCHOS_58.includes(n)) return '58MM';
      if (ANCHOS_80.includes(n)) return '80MM';
    }
  }
  return null;
}

// Modelos térmicos conocidos por nombre — cubre el caso en que el driver no
// declara un paper size legible (pasa con genéricos "Generic / Text Only").
// Sin dígito en el patrón -> térmica pero ancho desconocido, asumimos 80MM
// (mismo criterio "el lado que nunca corta" que el fallback de printTicket.js
// — angosto-en-rollo-ancho imprime completo, ancho-en-rollo-angosto recorta).
const PATRONES_TERMICA = [
  { re: /TM-T|TM-U|TSP\d|SRP-|BIXOLON|XPRINTER|XP-?58|POS-?58|GP-?58/i, ancho: '58MM' },
  { re: /XP-?80|POS-?80|GP-?80/i, ancho: '80MM' },
  { re: /RECEIPT|THERMAL|T[ée]rmica|RP-\d/i, ancho: '80MM' },
];

// Nombres de papel de oficina — si aparecen SIN ningún match de rollo, es
// evidencia negativa fuerte (impresora normal, no térmica).
const RE_OFICINA = /\b(A4|A3|Letter|Legal|Carta|Oficio|Ejecutivo|Estamento)\b/i;

function clasificar({ nombre, driverInfo, paperSizeActual, papelesSoportados }) {
  // 1) Ancho explícito en el tamaño configurado ahora mismo — la señal más
  //    confiable, es literalmente lo que el driver tiene cargado hoy.
  let ancho = anchoDesdeTexto(paperSizeActual);
  if (ancho) return { paperWidth: ancho, confidence: 'alta', fuente: 'PaperSize' };

  // 2) Ancho en la lista de papeles soportados por el driver.
  for (const nombrePapel of papelesSoportados || []) {
    ancho = anchoDesdeTexto(nombrePapel);
    if (ancho) return { paperWidth: ancho, confidence: 'alta', fuente: 'PrinterPaperNames' };
  }

  // 3) Nombre/modelo de la impresora — funciona incluso sin PowerShell (ver
  //    detectarPorNombre más abajo, usa esto solo con lo que ya da Electron).
  const texto = `${nombre || ''} ${driverInfo || ''}`;
  for (const p of PATRONES_TERMICA) {
    if (p.re.test(texto)) return { paperWidth: p.ancho, confidence: 'media', fuente: 'nombre' };
  }

  // 4) Negativo: solo tamaños de oficina, ningún indicio de rollo -> no es
  //    térmica. null explícito (no "80MM por defecto") para no inventar un
  //    ancho de receipt en una impresora que no imprime receipts.
  const todosLosPapeles = [paperSizeActual, ...(papelesSoportados || [])].filter(Boolean).join(' ');
  if (RE_OFICINA.test(todosLosPapeles)) return { paperWidth: null, confidence: 'alta', fuente: 'oficina' };

  return { paperWidth: null, confidence: 'baja', fuente: 'sin_datos' };
}

// Escapa comillas simples para interpolar el nombre de impresora en el
// -Command de PowerShell (nombres de impresora pueden traer espacios y
// paréntesis, ej. "HP33D753 (HP Smart Tank 580-590 series)" — nunca apóstrofes
// reales en la práctica, pero duplicarlos es gratis y evita romper el comando).
function psQuote(s) {
  return String(s || '').replace(/'/g, "''");
}

/**
 * Detecta el ancho probable de rollo para UNA impresora ya instalada en
 * Windows. Nunca lanza: cualquier falla (PowerShell bloqueado por política
 * de kiosco, impresora offline, timeout) devuelve paperWidth: null en vez
 * de tirar abajo el endpoint — la detección es un plus, no un requisito
 * para poder imprimir.
 */
async function detectarAnchoPapel(printerName, driverInfoElectron) {
  let paperSizeActual = null;
  let papelesSoportados = [];
  try {
    // $cfg.PaperSize.ToString(): probado en real, ConvertTo-Json serializa el
    // enum de PaperSize como el código numérico crudo de DMPAPER (ej. 9 para
    // A4), no como texto — .ToString() fuerza el nombre legible que después
    // sí matchea la regex de anchoDesdeTexto(). Sin PS7 en estas PCs (WinPS
    // 5.1) no hay operador ?. — el "if ($cfg)" evita romper con Get-Printer
    // Configuration devolviendo $null (impresora offline/no encontrada).
    const cmd =
      `$ErrorActionPreference='SilentlyContinue'; ` +
      `$cfg = Get-PrintConfiguration -PrinterName '${psQuote(printerName)}' 2>$null; ` +
      `$ps = if ($cfg) { $cfg.PaperSize.ToString() } else { '' }; ` +
      `$wmi = Get-CimInstance -ClassName Win32_Printer -Filter "Name='${psQuote(printerName).replace(/"/g, '`"')}'" 2>$null; ` +
      `$pap = if ($wmi) { ($wmi.PrinterPaperNames -join ',') } else { '' }; ` +
      `[PSCustomObject]@{ PaperSize = $ps; Papeles = $pap } | ConvertTo-Json -Compress`;
    const stdout = await runPowerShell(cmd);
    const parsed = JSON.parse(stdout);
    paperSizeActual = parsed.PaperSize || null;
    papelesSoportados = (parsed.Papeles || '').split(',').map((s) => s.trim()).filter(Boolean);
  } catch (err) {
    // PowerShell bloqueado, timeout, o impresora no encontrada: seguimos solo
    // con lo que ya tenemos del nombre (electron-make-and-model).
    log.warn(`Detección de papel para "${printerName}" sin datos de PowerShell: ${err.message}`);
  }

  const resultado = clasificar({ nombre: printerName, driverInfo: driverInfoElectron, paperSizeActual, papelesSoportados });
  return { printerName, ...resultado, paperSizeActual, papelesSoportados };
}

module.exports = { detectarAnchoPapel, clasificar, anchoDesdeTexto };
