// TuResto Print Agent - lib/htmlValidator.js
//
// El agente acepta HTML (no PDF — printTicket.js arma el ticket como HTML y
// lo manda directo, ver queue.js printOnce() que lo carga como data: URL en
// una BrowserWindow oculta). Sin validar, alguien con el Bearer token podría:
//  - Mandar payloads gigantes (saturar disco/memoria vía la cola persistida).
//  - Embeber <script>/<iframe>/recursos remotos: la ventana de impresión
//    tiene salida de red real (es un renderer de Chromium con networking
//    normal) — eso la vuelve un vector de SSRF/exfiltración ciego apuntado
//    a localhost u otras IPs de la LAN del local, algo que un ticket de
//    cocina/caja JAMÁS necesita.
//
// No se sanitiza in-place (no hay caso de uso legítimo para JS/recursos
// remotos en un ticket) — se rechaza derecho.

const MAX_HTML_SIZE = 2 * 1024 * 1024; // 2MB: un ticket real pesa unos KB, esto deja margen de sobra
const MAX_COPIES = 20;

function validateHtml(html) {
  if (!html || typeof html !== 'string') {
    throw new Error('HTML no proporcionado');
  }

  const size = Buffer.byteLength(html, 'utf8');
  if (size > MAX_HTML_SIZE) {
    throw new Error(`HTML demasiado grande: ${(size / 1024 / 1024).toFixed(1)}MB. Máximo ${MAX_HTML_SIZE / 1024 / 1024}MB`);
  }

  // No exigir <html>/<body> (printTicket.js a veces manda fragmentos), pero
  // sí algo de markup real — un payload vacío o puro texto no es un ticket.
  if (!/<[a-z][\s\S]*>/i.test(html)) {
    throw new Error('El contenido no parece HTML válido');
  }

  if (/<script[\s>]/i.test(html)) {
    throw new Error('HTML con <script> no permitido');
  }

  if (/<iframe[\s>]|<embed[\s>]|<object[\s>]/i.test(html)) {
    throw new Error('HTML con contenido embebido no permitido');
  }

  // Cualquier referencia a un recurso remoto (img/link/src con http(s)://) —
  // la ventana de impresión tiene red real, así que esto sería SSRF ciego.
  // Los tickets usan estilos inline y, cuando hay logo, una ruta propia del
  // backend de TuResto (turesto.pro) — eso también es "remoto" en sentido
  // estricto, pero es el origen ya confiado por CORS/Bearer para esta misma
  // request, así que se permite explícitamente.
  //
  // El host se compara PARSEANDO la URL, no buscando "turesto.pro" adentro del
  // texto: con un substring, http://evil.com/?x=turesto.pro pasaba como propio.
  // Igual esto es la primera de dos barreras — la que decide de verdad es el
  // filtro de red de la ventana de impresión (queue.js), porque una URL puede
  // esconderse en lugares que este regex no mira (background:url(...) en un
  // style, @import en un <style>, srcset, //host sin protocolo).
  const remoteRefs = html.match(/(?:src|href)\s*=\s*["'](https?:)?\/\/[^"']+["']/gi) || [];
  const remotoNoConfiable = remoteRefs.some((ref) => {
    const cruda = ref.replace(/^[^=]*=\s*["']/, '').replace(/["']$/, '');
    try {
      const { hostname } = new URL(cruda.startsWith('//') ? `https:${cruda}` : cruda);
      return !/(^|\.)turesto\.pro$/i.test(hostname);
    } catch {
      return true;   // si no parsea, no se confía
    }
  });
  if (remotoNoConfiable) {
    throw new Error('HTML con referencias a recursos remotos no permitido');
  }

  return { size };
}

function validateCopies(copies) {
  const n = Number(copies) || 1;
  if (n < 1 || n > MAX_COPIES) {
    throw new Error(`Cantidad de copias inválida (máximo ${MAX_COPIES})`);
  }
  return n;
}

module.exports = { validateHtml, validateCopies, MAX_HTML_SIZE, MAX_COPIES };
