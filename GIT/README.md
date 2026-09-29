# Respaldo del Proyecto - Descargador SharePoint / HLS

Este directorio contiene la versión respaldada del código fuente y documentación del proyecto de descarga de videos protegidos de SharePoint.

## Contenido del Respaldo

- **`descarga_hls.py`**: Script principal para el análisis HLS, descarga paralela de segmentos (`.m4s`), descifrado AES-128-CBC con desacolchado (unpadding) por segmento, y muxing con FFmpeg.
- **`descarga_sharepoint.py`**: Script de soporte para autenticación y extracción de manifiestos DASH/HLS en SharePoint.
- **`headers.json`**: Plantilla de cabeceras de sesión requeridas para la autenticación HTTP con SharePoint.
- **`DOCUMENTACION.md`**: Guía técnica detallada sobre la arquitectura y funcionamiento del sistema.

---
*Nota: Los archivos binarios pesados (`ffmpeg.exe`) y los videos descargados (`.mp4`) se excluyen de este respaldo para mantener un tamaño ligero apto para control de versiones (Git).*
