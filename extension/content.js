// Puente página ↔ extensión, inyectado en turesto.pro.
//
// La página (printAgent.js) no puede llamar a chrome.* ni conoce el ID de la
// extensión, así que hablamos por window.postMessage. Este content script
// reenvía al service worker (que sí habla con el agente local) y devuelve la
// respuesta con el mismo `requestId`, para que la web pueda correlacionar
// múltiples pedidos en simultáneo.

const TYPES = ['TURESTO_HEALTH', 'TURESTO_PAIR_REQUEST', 'TURESTO_PAIR_CLAIM', 'TURESTO_GET_PRINTERS', 'TURESTO_PRINT', 'TURESTO_REFRESH_TOKEN'];

function anunciar() {
  window.postMessage({ type: 'TURESTO_EXTENSION_READY' }, '*');
}
anunciar();

window.addEventListener('message', (ev) => {
  if (ev.source !== window || !ev.data) return;
  const { type, payload, requestId } = ev.data;

  if (type === 'TURESTO_EXTENSION_PING') {
    anunciar();
    return;
  }
  if (!TYPES.includes(type)) return;

  chrome.runtime.sendMessage({ type, payload }, (resp) => {
    const err = chrome.runtime.lastError;
    if (err) {
      window.postMessage({ type: `${type}_RESPONSE`, requestId, success: false, error: err.message }, '*');
      return;
    }
    window.postMessage({ type: `${type}_RESPONSE`, requestId, ...(resp || { success: false, error: 'Sin respuesta del agente.' }) }, '*');
  });
});
