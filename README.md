# Descargador de Video SharePoint / Stream (HLS + AES-128)

Solución automatizada de alta velocidad para descargar videos protegidos en enlaces compartidos de SharePoint / Microsoft Stream mediante el protocolo **HLS (HTTP Live Streaming)** con descifrado **AES-128-CBC** integrado y unión (muxing) con **FFmpeg**.

---

## 🚀 Guía Rápida de Uso

1. **Requisitos:**
   - Python 3.x
   - Dependencias: `pip install requests pycryptodome beautifulsoup4`
   - FFmpeg (`ffmpeg.exe` en el directorio del proyecto o en el PATH).

2. **Configuración de Credenciales (`headers.json`):**
   Crea o actualiza el archivo `headers.json` con tu token de sesión capturado de SharePoint:
   ```json
   {
       "headers": {
           "x-spopactoken": "TU_TOKEN_SPOP_AQUI",
           "accept": "*/*",
           "origin": "https://tu-tenant-my.sharepoint.com",
           "referer": "https://tu-tenant-my.sharepoint.com/"
       },
       "cookies": {}
   }
   ```

3. **Ejecución:**
   ```bash
   python descarga_hls.py
   ```

---

## 📚 Documentación Completa

Para una explicación detallada de la arquitectura, manejo de segmentos HLS, descifrado AES-128-CBC por segmento y desacolchado (unpadding), consulta el archivo **[DOCUMENTACION.md](DOCUMENTACION.md)**.
