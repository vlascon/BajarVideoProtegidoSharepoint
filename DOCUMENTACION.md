# Documentación del Descargador de SharePoint / Stream (HLS + AES-128)

Este proyecto implementa una solución automatizada de alta velocidad para descargar videos protegidos en enlaces compartidos de SharePoint / Microsoft Stream mediante el protocolo **HLS (HTTP Live Streaming)** con descifrado **AES-128-CBC** integrado y unión (muxing) con **FFmpeg**.

---

## 1. Arquitectura y Estrategia de Descarga

Los videos alojados en SharePoint Media Service emplean seguridad avanzada (URLs firmadas, tokens de sesión y cifrado AES-128 por segmentos). El proceso consta de las siguientes fases:

1. **Autenticación y Captura de Cabeceras (`headers.json`):**
   - Se requiere un token de sesión válido (`x-spopactoken`) obtenido desde las herramientas de desarrollo del navegador (F12 > Red/Network) al reproducir el video en SharePoint.

2. **Resolución del Manifiesto Maestro (`videomanifest`):**
   - El script consulta el manifiesto HLS maestro, extrayendo las URLs de las sub-playlists de **video** y **audio**, así como la variable global de clave (`commonVpkUrlVariable` para el descifrado AES).
   - *Nota:* Para evitar obtener una muestra limitada o fragmento corto (ej. `altManifestMetadata`), se solicita el manifiesto completo omitiendo restricciones de segmento.

3. **Parseo de Sub-Playlists:**
   - Cada sub-playlist (video y audio) contiene:
     - El segmento de inicialización (`#EXT-X-MAP:URI="init.mp4"`).
     - La clave de cifrado (`#EXT-X-KEY:METHOD=AES-128`, con su respectivo `URI` e `IV`).
     - La lista completa de segmentos multimedia cifrados y planos (`.m4s`).

4. **Descarga Paralela:**
   - Utiliza `ThreadPoolExecutor` para descargar los cientos de segmentos multimedia en paralelo de forma eficiente.

5. **Descifrado AES-128-CBC y Desacolchado (Unpadding):**
   - Los segmentos cifrados se descifran utilizando la clave AES obtenida y el vector de inicialización (`IV`).
   - Cada segmento HLS se desacopla individualmente (Padding PKCS7) para asegurar la integridad de las cajas fMP4 (`moof`/`mdat`).

6. **Muxing con FFmpeg:**
   - Una vez reconstruidos los archivos temporales de video (`temp_video.mp4`) y audio (`temp_audio.mp4`), se combinan en un único archivo MP4 optimizado para reproducción (`-movflags +faststart`).

---

## 2. Estructura del Proyecto

```text
├── 2026-09-28_video_sharepoint.mp4  # Video final resultante (unido)
├── descarga_hls.py                  # Script principal optimizado para descarga HLS paralela y descifrado
├── descarga_sharepoint.py           # Script auxiliar de análisis y autenticación SharePoint
├── ffmpeg.exe                       # Binario oficial de FFmpeg para muxing
├── headers.json                     # Almacenamiento seguro de cabeceras y tokens de sesión
└── DOCUMENTACION.md                 # Esta documentación
```

---

## 3. Uso y Configuración

### Configuración de `headers.json`
Crea o actualiza el archivo `headers.json` con tus cabeceras capturadas del navegador:
```json
{
    "headers": {
        "x-spopactoken": "YOUR_SPOP_ACTIVATION_TOKEN_HERE",
        "accept": "*/*",
        "origin": "https://YOUR_TENANT-my.sharepoint.com",
        "referer": "https://YOUR_TENANT-my.sharepoint.com/"
    },
    "cookies": {}
}
```

### Ejecución de `descarga_hls.py`
El script carga las cabeceras, resuelve el manifiesto maestro, descarga los segmentos de video y audio en paralelo, los descifra y genera el archivo MP4 final.

```bash
python descarga_hls.py
```

---

## 4. Consideraciones Técnicas y Buenas Prácticas

- **Expiración de Tokens:** Los tokens de SharePoint y las URLs firmadas de Media Service caducan tras cierto tiempo. Si falla la descarga, captura un nuevo `x-spopactoken` y actualiza la URL maestra en el script.
- **Integridad de Segmentos:** Al trabajar con streams HLS fragmentados (`.m4s`), aplicar la eliminación de padding PKCS7 (`unpad_pkcs7`) por cada segmento cifrado es fundamental; de lo contrario, los offsets del contenedor MP4 se corrompen y FFmpeg reportará una duración incorrecta (ej. sólo unos pocos segundos).
- **Dependencias:** Requiere Python 3.x, `requests` y `pycryptodome` (`pip install requests pycryptodome beautifulsoup4`).
