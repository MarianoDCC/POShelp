// Service worker de la extensión TuResto Impresión.
//
// POR QUÉ EXISTE: una página HTTPS pública (turesto.pro) no puede hablar de
// forma confiable con un servidor en 127.0.0.1 (el navegador lo bloquea por
// Private Network Access). La extensión sí puede: tiene host_permissions
// sobre el agente local. La web le pide a la extensión, y la extensión habla
// con el agente, reenviando el Bearer token que la web ya tiene guardado.

const AGENT = 'http://127.0.0.1:47823';

async function llamarAgente(type, payload) {
  if (type === 'TURESTO_HEALTH') {
    const r = await fetch(`${AGENT}/health`);
    const body = await r.json();
    return body.data;
  }

  if (type === 'TURESTO_PAIR_REQUEST') {
    const r = await fetch(`${AGENT}/pair/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: payload?.code }),
    });
    const body = await r.json();
    if (!r.ok || !body.success) throw new Error(body.error || 'Código incorrecto o vencido.');
    return { token: body.token, machine: body.machine };
  }

  if (type === 'TURESTO_PAIR_CLAIM') {
    const r = await fetch(`${AGENT}/pair/claim`);
    const body = await r.json();
    return { success: !!body.success, token: body.token, machine: body.machine };
  }

  if (type === 'TURESTO_GET_PRINTERS') {
    const r = await fetch(`${AGENT}/printers`, { headers: { Authorization: `Bearer ${payload?.token}` } });
    const body = await r.json();
    if (!r.ok || !body.success) throw tokenError(r, body);
    return { printers: body.printers, tokenExpiresWarningDays: tokenWarningDays(r) };
  }

  // Ancho de rollo detectado (best-effort, botón "Detectar automáticamente"
  // en Ajustes > Área de Impresión) — mismo puente que /printers, agentes
  // viejos sin este endpoint devuelven 404 y el llamador cae al selector manual.
  if (type === 'TURESTO_DETECT_PAPER') {
    const r = await fetch(`${AGENT}/printer-config?name=${encodeURIComponent(payload?.printerName || '')}`, {
      headers: { Authorization: `Bearer ${payload?.token}` },
    });
    const body = await r.json();
    if (!r.ok || !body.success) throw tokenError(r, body);
    return body;
  }

  if (type === 'TURESTO_PRINT') {
    const { token, ...rest } = payload || {};
    const r = await fetch(`${AGENT}/print`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(rest),
    });
    const body = await r.json();
    if (!r.ok || !body.success) throw tokenError(r, body);
    return { jobId: body.jobId, status: body.status, tokenExpiresWarningDays: tokenWarningDays(r) };
  }

  // Renueva el token actual (mismo valor, vencimiento +30 días) sin pedirle
  // un código nuevo al usuario — la web lo dispara sola cuando ve
  // tokenExpiresWarningDays en una respuesta previa (ver printAgent.js).
  if (type === 'TURESTO_REFRESH_TOKEN') {
    const r = await fetch(`${AGENT}/auth/refresh`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${payload?.token}` },
    });
    const body = await r.json();
    if (!r.ok || !body.success) throw new Error(body.error || 'No se pudo renovar el token.');
    return { token: body.token, expiresAt: body.expiresAt };
  }

  throw new Error('Tipo de mensaje desconocido.');
}

// El agente marca con este header cuando al token le quedan <=7 días — se
// usa para disparar un refresh automático sin que el usuario note nada.
function tokenWarningDays(r) {
  const v = r.headers.get('X-Token-Expires-Warning');
  return v != null ? Number(v) : null;
}

// El código NOT_PAIRED/NO_TOKEN/INVALID_TOKEN del agente (ver authMiddleware
// en server.js) le dice a printAgent.js que tiene que mostrar "vinculá de
// nuevo" en vez de un error genérico de impresión.
function tokenError(r, body) {
  const err = new Error(body.error || `Error del agente (${r.status})`);
  err.code = body.code;
  return err;
}

// El content script (en turesto.pro) reenvía acá los pedidos de la página.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type) return;
  llamarAgente(msg.type, msg.payload)
    .then((data) => sendResponse({ success: true, data }))
    .catch((e) => sendResponse({ success: false, error: String((e && e.message) || e), code: e && e.code }));
  return true; // respuesta asíncrona
});
