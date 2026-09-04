; TuResto Print Agent - build/installer.nsh
;
; POR QUÉ: el agente no tiene NINGUNA ventana (a propósito, ver main.js — es
; un proceso de fondo puro). El mecanismo por defecto de electron-builder
; para "cerrar la app antes de instalar" busca una VENTANA de la app y le
; manda WM_CLOSE — sin ventana que encontrar, esa lógica no tiene nada que
; cerrar, así que una actualización silenciosa (/S) sobre una instalación
; con el agente corriendo dejaba el .exe/app.asar viejo BLOQUEADO por el
; proceso vivo: los archivos nuevos no se copiaban encima (reportado:
; reinstalar no sustituía nada, quedaba corriendo la versión anterior).
;
; customInit corre apenas arranca el instalador, antes de tocar ningún
; archivo — matar el proceso acá (por nombre de imagen, no por ventana)
; libera los locks a tiempo para que la extracción de abajo sí reemplace
; todo. /T mata también los procesos hijos (Electron levanta un renderer
; oculto para imprimir, ver queue.js) para no dejar huérfanos.

!macro customInit
  DetailPrint "Cerrando TuResto Impresión si está corriendo…"
  nsExec::ExecToLog 'taskkill /F /IM "TuResto Impresión.exe" /T'
  Pop $0
  ; Pequeño respiro para que Windows termine de soltar los handles de
  ; archivo antes de que NSIS intente sobreescribirlos.
  Sleep 500
!macroend

; Mismo problema al desinstalar: si el agente sigue corriendo, "Eliminar
; datos de la app" (deleteAppDataOnUninstall) y el borrado de archivos
; pueden fallar a mitad de camino por los mismos locks.
!macro customUnInit
  DetailPrint "Cerrando TuResto Impresión si está corriendo…"
  nsExec::ExecToLog 'taskkill /F /IM "TuResto Impresión.exe" /T'
  Pop $0
  Sleep 500
!macroend
