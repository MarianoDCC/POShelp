# TuResto Impresión — Extensión de Chrome

Puente entre el POS (turesto.pro) y el **agente de impresión local**. Mismo modelo
que Fudo: la **aplicación** (carpeta `print-agent/`) imprime, y esta **extensión**
es el canal confiable entre la web y la app.

## ¿Por qué una extensión?

Una página HTTPS pública no puede hablar de forma confiable con un servidor en
`127.0.0.1` (el navegador lo bloquea por *Private Network Access*). La extensión
sí puede, y así la detección y la impresión dejan de fallar.

Si la extensión está instalada, el POS la usa automáticamente. Si no, cae al
método directo (fetch a `127.0.0.1`) de antes.

## Instalar (mientras no esté en la Chrome Web Store)

1. Abrí `chrome://extensions`.
2. Activá **Modo de desarrollador** (arriba a la derecha).
3. **Cargar descomprimida** → elegí esta carpeta (`print-extension`).
4. Listo. Abrí el POS y, en el badge de impresión, **Detectar**.

> Requiere que la **aplicación** (`print-agent/`) esté corriendo: es la que
> realmente manda a la impresora.

## Vinculación

Esta extensión solo es el canal; la seguridad real es el pairing por código
de 6 dígitos + Bearer token, que vive en el agente (`print-agent/`). Ver
`print-agent/README.md`. Tras cargar la extensión, copiá su ID (visible en
`chrome://extensions`) y agregalo a `ALLOWED_EXTENSION_IDS` en
`print-agent/lib/config.js` antes de distribuir el instalador en producción.

## Publicación (futuro)

Para instalación de un clic, se publica en la Chrome Web Store (cuenta de
desarrollador). El código no cambia; sólo se sube esta carpeta empaquetada.
