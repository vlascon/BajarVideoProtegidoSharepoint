#!/usr/bin/env python3
"""
descarga_sharepoint.py — Descargador de video SharePoint protegido con contraseña.

Estrategia A: Descarga directa del MP4 original.
Estrategia B: Reconstrucción desde stream DASH (descifrado AES-128-CBC).

Uso:
    python descarga_sharepoint.py --url "URL" --password "PASS" --output "archivo.mp4"
"""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs, unquote

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0"
)

CHUNK_SIZE = 1024 * 1024  # 1 MB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def progress_bar(current, total, prefix="", bar_len=40):
    """Muestra una barra de progreso en la consola."""
    if total <= 0:
        pct = 0
    else:
        pct = current / total
    filled = int(bar_len * pct)
    bar = "█" * filled + "░" * (bar_len - filled)
    mb_curr = current / (1024 * 1024)
    mb_total = total / (1024 * 1024)
    sys.stdout.write(
        f"\r{prefix} [{bar}] {pct*100:5.1f}%  {mb_curr:.1f}/{mb_total:.1f} MB"
    )
    sys.stdout.flush()


def verify_mp4(filepath):
    """Verificación básica del archivo MP4 descargado."""
    size = os.path.getsize(filepath)
    print(f"\n{'='*60}")
    print(f"  VERIFICACIÓN DEL ARCHIVO")
    print(f"{'='*60}")
    print(f"  Archivo:  {filepath}")
    print(f"  Tamaño:   {size:,} bytes ({size/(1024*1024):.2f} MB)")

    # SHA-256
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    print(f"  SHA-256:  {sha.hexdigest()}")

    # Verificar encabezado ftyp
    with open(filepath, "rb") as f:
        header = f.read(12)
    if b"ftyp" in header:
        print("  Formato:  ✅ MP4 válido (ftyp box detectada)")
    else:
        print("  Formato:  ⚠️  No se detectó ftyp box (puede ser fragmentado)")

    print(f"{'='*60}\n")
    return size > 0


# ---------------------------------------------------------------------------
# Fase 1: Autenticación con contraseña (Guest Access)
# ---------------------------------------------------------------------------
class SharePointAuth:
    """Maneja la autenticación en un enlace SharePoint protegido con contraseña."""

    def __init__(self, shared_url, password):
        self.shared_url = shared_url
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-CL,es;q=0.9,en;q=0.8",
        })
        self.authenticated = False
        self.final_url = None  # URL después de autenticación
        self.base_url = None   # Base del tenant SharePoint

        parsed = urlparse(shared_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"

    def authenticate(self):
        """Realiza el flujo completo de autenticación con contraseña."""
        print("\n[Fase 1] Autenticando con contraseña...")
        print(f"  URL: {self.shared_url[:80]}...")

        # Paso 1: GET inicial para obtener cookies y la página de contraseña
        print("  [1.1] GET inicial al enlace compartido...")
        resp = self.session.get(self.shared_url, allow_redirects=True)
        print(f"    Status: {resp.status_code}")
        print(f"    URL final: {resp.url[:80]}...")

        # Si ya tenemos acceso sin contraseña, salir
        if "Validación de vínculo" not in resp.text and "guestaccess" not in resp.url.lower():
            # Chequear si ya estamos en la página del video
            if "onedrive" in resp.url.lower() or "stream" in resp.text.lower() or resp.status_code == 200:
                print("    ℹ️  Parece que no se requiere contraseña o ya hay sesión activa.")
                self.final_url = resp.url
                self.authenticated = True
                return True

        # Paso 2: Analizar la página de contraseña
        print("  [1.2] Analizando página de contraseña...")
        auth_success = self._try_sharepoint_password_auth(resp)

        if auth_success:
            print("  ✅ Autenticación exitosa!")
            self.authenticated = True
            return True

        print("  ❌ No se pudo autenticar automáticamente.")
        return False

    def _try_sharepoint_password_auth(self, initial_resp):
        """Intenta autenticarse con la contraseña parseando la página."""

        # La página de contraseña de SharePoint usa JavaScript para enviar el POST.
        # Necesitamos identificar la URL de destino y los campos del formulario.
        html = initial_resp.text
        soup = BeautifulSoup(html, "html.parser")

        # Buscar el script que contiene la configuración de SPOGuestAccess
        # El formulario de contraseña de SharePoint usa un POST a la misma URL 
        # o a _layouts/15/guestaccess.aspx con los datos del formulario.
        
        # Estrategia 1: Buscar _spModuleLink y el bundle JS que maneja el password
        # Típicamente el POST va a la misma URL con el body correcto
        
        post_url = initial_resp.url

        # Extraer cualquier token de la página
        request_digest = None
        digest_input = soup.find("input", {"name": "__REQUESTDIGEST"})
        if digest_input:
            request_digest = digest_input.get("value", "")
        
        # Extraer FormDigestValue del JavaScript embebido
        digest_match = re.search(r'"FormDigestValue"\s*:\s*"([^"]+)"', html)
        if digest_match:
            request_digest = digest_match.group(1)

        # Intentar varios métodos de POST de contraseña
        methods = [
            self._try_method_json_post,
            self._try_method_form_post,
            self._try_method_guestaccess_post,
            self._try_method_api_verify,
        ]

        for method in methods:
            print(f"    Probando {method.__name__}...")
            try:
                result = method(post_url, request_digest, initial_resp)
                if result:
                    return True
            except Exception as e:
                print(f"      Error: {e}")
                continue

        return False

    def _try_method_json_post(self, post_url, digest, initial_resp):
        """POST JSON con contraseña (formato moderno SPO)."""
        # SharePoint moderno usa un POST JSON a la URL con ?action=verify
        verify_url = post_url
        if "?" in verify_url:
            verify_url += "&verify=1"
        else:
            verify_url += "?verify=1"

        headers = {
            "Content-Type": "application/json;odata=verbose",
            "Accept": "application/json",
        }
        if digest:
            headers["X-RequestDigest"] = digest

        payload = json.dumps({"password": self.password})
        resp = self.session.post(verify_url, data=payload, headers=headers, allow_redirects=True)

        if resp.status_code == 200 and "FedAuth" in str(self.session.cookies):
            self.final_url = resp.url
            return True
        return False

    def _try_method_form_post(self, post_url, digest, initial_resp):
        """POST form-encoded con contraseña."""
        data = {"PasswordFormData": self.password}
        if digest:
            data["__REQUESTDIGEST"] = digest

        resp = self.session.post(post_url, data=data, allow_redirects=True)

        if resp.status_code == 200 and "Validación de vínculo" not in resp.text:
            self.final_url = resp.url
            if "FedAuth" in str(self.session.cookies):
                return True
            # A veces no hay FedAuth pero sí tenemos acceso
            if len(resp.text) > 5000:  # Página real cargada
                return True
        return False

    def _try_method_guestaccess_post(self, post_url, digest, initial_resp):
        """POST a _layouts/15/guestaccess.aspx."""
        parsed = urlparse(post_url)
        guestaccess_url = f"{parsed.scheme}://{parsed.netloc}/_layouts/15/guestaccess.aspx"

        # Extraer parámetros del URL original
        params = parse_qs(parsed.query)
        
        data = {
            "PasswordFormData": self.password,
            "password": self.password,
        }
        if digest:
            data["__REQUESTDIGEST"] = digest

        # Pasar parámetros originales como query string
        resp = self.session.post(
            guestaccess_url,
            data=data,
            params=params,
            allow_redirects=True,
        )

        if resp.status_code == 200 and "FedAuth" in str(self.session.cookies):
            self.final_url = resp.url
            return True
        return False

    def _try_method_api_verify(self, post_url, digest, initial_resp):
        """POST a la API de verificación de SharePoint."""
        # Extraer el sharing token del URL original
        parsed = urlparse(self.shared_url)
        path_parts = parsed.path.split("/")

        # Construir URL de verificación tipo REST
        # _api/SP.Sharing.ShareLinkManager.ValidatePassword
        api_base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Intentar el endpoint de verificación de contraseña
        verify_endpoints = [
            f"{api_base}/_api/SP.Sharing.ShareLinkManager.ValidatePassword",
            f"{api_base}{'/'.join(parsed.path.split('/')[:4])}/_api/SP.Sharing.ShareLinkManager.ValidatePassword",
        ]

        headers = {
            "Content-Type": "application/json;odata=verbose",
            "Accept": "application/json;odata=verbose",
        }
        if digest:
            headers["X-RequestDigest"] = digest

        payload = json.dumps({
            "password": self.password,
            "shareLink": self.shared_url,
        })

        for endpoint in verify_endpoints:
            try:
                resp = self.session.post(endpoint, data=payload, headers=headers, allow_redirects=True)
                if resp.status_code == 200:
                    self.final_url = self.shared_url
                    return True
            except Exception:
                continue

        return False


# ---------------------------------------------------------------------------
# Estrategia A: Descarga directa
# ---------------------------------------------------------------------------
class DirectDownloader:
    """Intenta descargar el MP4 directamente desde SharePoint."""

    def __init__(self, session, shared_url, base_url):
        self.session = session
        self.shared_url = shared_url
        self.base_url = base_url

    def try_download(self, output_path):
        """Intenta la descarga directa. Retorna True si exitosa."""
        print("\n[Estrategia A] Intentando descarga directa...")

        methods = [
            ("URL con download=1", self._try_download_param),
            ("Transformar URL a formato download", self._try_url_transform),
            ("API v2.0 /content", self._try_api_v2_content),
            ("URL con action=download", self._try_action_download),
        ]

        for name, method in methods:
            print(f"  Probando: {name}...")
            try:
                resp = method()
                if resp and self._is_downloadable(resp):
                    print(f"    ✅ Descarga directa disponible!")
                    return self._save_stream(resp, output_path)
            except Exception as e:
                print(f"    ❌ Error: {e}")
                continue

        print("  ⚠️  Descarga directa no disponible. Pasando a Estrategia B...")
        return False

    def _try_download_param(self):
        """Añade download=1 al URL."""
        sep = "&" if "?" in self.shared_url else "?"
        url = f"{self.shared_url}{sep}download=1"
        return self.session.get(url, stream=True, allow_redirects=True, timeout=30)

    def _try_url_transform(self):
        """Transforma :v: a :u: (formato de descarga de OneDrive)."""
        download_url = self.shared_url.replace("/:v:/", "/:u:/")
        sep = "&" if "?" in download_url else "?"
        download_url = f"{download_url}{sep}download=1"
        return self.session.get(download_url, stream=True, allow_redirects=True, timeout=30)

    def _try_api_v2_content(self):
        """Intenta usar la API v2.0 de OneDrive/SharePoint."""
        # Extraer el path del personal site
        parsed = urlparse(self.shared_url)
        path_parts = parsed.path.split("/")

        # Buscar el segmento 'personal/xxx'
        personal_path = None
        for i, part in enumerate(path_parts):
            if part == "personal" and i + 1 < len(path_parts):
                personal_path = f"/personal/{path_parts[i+1]}"
                break

        if not personal_path:
            return None

        # Intentar obtener info del item via API
        api_base = f"{self.base_url}{personal_path}/_api/v2.0"

        # Primero obtener info del shared item
        headers = {"Accept": "application/json"}
        info_url = f"{api_base}/shares/u!{self._encode_sharing_url()}/driveItem"
        try:
            resp = self.session.get(info_url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                download_url = data.get("@microsoft.graph.downloadUrl") or data.get("@content.downloadUrl")
                if download_url:
                    return self.session.get(download_url, stream=True, allow_redirects=True, timeout=30)
        except Exception:
            pass

        return None

    def _try_action_download(self):
        """Intenta ?action=download."""
        sep = "&" if "?" in self.shared_url else "?"
        url = f"{self.shared_url}{sep}action=download"
        return self.session.get(url, stream=True, allow_redirects=True, timeout=30)

    def _encode_sharing_url(self):
        """Codifica el URL de sharing para la API de Graph."""
        encoded = base64.urlsafe_b64encode(self.shared_url.encode()).decode()
        return encoded.rstrip("=")

    def _is_downloadable(self, resp):
        """Verifica si la respuesta contiene un archivo descargable."""
        if resp.status_code != 200:
            print(f"    Status: {resp.status_code}")
            return False

        content_type = resp.headers.get("Content-Type", "")
        content_disp = resp.headers.get("Content-Disposition", "")
        content_len = int(resp.headers.get("Content-Length", "0"))

        print(f"    Content-Type: {content_type}")
        print(f"    Content-Length: {content_len:,} bytes")

        # Es un archivo de video
        if "video/" in content_type or "application/octet-stream" in content_type:
            if content_len > 1_000_000:  # Al menos 1 MB
                return True

        # Tiene Content-Disposition con attachment
        if "attachment" in content_disp:
            return True

        # Es un archivo grande (probablemente video)
        if content_len > 10_000_000:  # > 10 MB
            return True

        return False

    def _save_stream(self, resp, output_path):
        """Guarda la respuesta streaming a un archivo."""
        total = int(resp.headers.get("Content-Length", "0"))
        downloaded = 0

        print(f"\n  Descargando a: {output_path}")
        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    progress_bar(downloaded, total, prefix="  Descarga")

        print()  # Nueva línea después de la barra de progreso
        return True


# ---------------------------------------------------------------------------
# Estrategia B: Reconstrucción desde DASH
# ---------------------------------------------------------------------------
class DashDownloader:
    """Descarga y reconstruye video desde stream DASH cifrado."""

    def __init__(self, session, shared_url, base_url):
        self.session = session
        self.shared_url = shared_url
        self.base_url = base_url

    def try_download(self, output_path, forced_manifest_url=None):
        """Intenta descargar via DASH stream. Retorna True si exitosa."""
        print("\n[Estrategia B] Intentando reconstrucción desde stream DASH...")

        # Paso 1: Encontrar el manifest URL
        if forced_manifest_url:
            manifest_url = forced_manifest_url
        else:
            manifest_url = self._find_manifest_url()
        
        if not manifest_url:
            print("  ❌ No se pudo encontrar el manifest DASH.")
            return False

        print(f"  Manifest: {manifest_url[:80]}...")

        # Paso 2: Descargar y parsear el manifest
        manifest_resp = self.session.get(manifest_url)
        if manifest_resp.status_code != 200:
            print(f"  ❌ Error obteniendo manifest: {manifest_resp.status_code}")
            return False

        mpd_content = manifest_resp.text
        print(f"  Manifest descargado ({len(mpd_content):,} bytes)")

        # Paso 3: Parsear el manifest
        segments_info = self._parse_manifest(mpd_content, manifest_url)
        if not segments_info:
            print("  ❌ No se pudo parsear el manifest.")
            return False

        # Paso 4: Obtener la clave de descifrado (si hay cifrado)
        key = None
        iv = None
        if segments_info.get("key_url"):
            print("  [B.3] Obteniendo clave de descifrado...")
            key, iv = self._get_decryption_key(segments_info)
            if key:
                print(f"    Clave obtenida ({len(key)} bytes)")
            else:
                print("    ⚠️  No se pudo obtener la clave. Intentando sin descifrado...")

        # Paso 5: Descargar segmentos
        temp_dir = tempfile.mkdtemp(prefix="sp_dash_")
        print(f"  [B.4] Directorio temporal: {temp_dir}")

        video_file = self._download_segments(
            segments_info.get("video_segments", []),
            key, iv, temp_dir, "video"
        )
        audio_file = self._download_segments(
            segments_info.get("audio_segments", []),
            key, iv, temp_dir, "audio"
        )

        if not video_file:
            print("  ❌ No se pudieron descargar los segmentos de video.")
            return False

        # Paso 6: Ensamblar
        print("  [B.5] Ensamblando archivo final...")
        success = self._assemble(video_file, audio_file, output_path, temp_dir)

        # Limpiar
        try:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

        return success

    def _find_manifest_url(self):
        """Busca la URL del manifest DASH en la página del video."""
        print("  [B.1] Buscando manifest DASH...")

        # Intentar obtener la página del video
        resp = self.session.get(self.shared_url, allow_redirects=True)

        # Buscar URLs de videomanifest en el HTML/JS
        patterns = [
            r'(https?://[^\s"\']+videomanifest[^\s"\']*)',
            r'(https?://[^\s"\']+\.mpd[^\s"\']*)',
            r'"manifestUrl"\s*:\s*"([^"]+)"',
            r'"videoManifestUrl"\s*:\s*"([^"]+)"',
            r'"mediaBaseUrl"\s*:\s*"([^"]+)"',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, resp.text)
            if matches:
                url = matches[0].replace("\\u002f", "/").replace("\\/", "/")
                return url

        # Intentar construir la URL del manifest a partir del shared URL
        manifest_url = self._construct_manifest_url()
        if manifest_url:
            # Verificar que funciona
            test = self.session.get(manifest_url, timeout=10)
            if test.status_code == 200 and ("MPD" in test.text or "xml" in test.text.lower()):
                return manifest_url

        # Buscar en la API de SharePoint
        manifest_url = self._find_manifest_via_api()
        return manifest_url

    def _construct_manifest_url(self):
        """Construye la URL del manifest basándose en la URL compartida."""
        parsed = urlparse(self.shared_url)

        # Extraer el ID del item del path (:v: link)
        # Formato: /personal/user/_layouts/15/stream.aspx?id=...
        # o: /:v:/g/personal/user/ITEM_ID

        # Para links de tipo :v:, el path contiene el encoded item
        path = parsed.path
        if "/:v:/" in path:
            # Extraer el segmento después de personal/user/
            parts = path.split("/")
            # Buscar el ID codificado
            for i, p in enumerate(parts):
                if p == "personal" and i + 2 < len(parts):
                    user = parts[i + 1]
                    item_encoded = parts[i + 2] if i + 2 < len(parts) else None
                    if item_encoded:
                        # Intentar construir URL de videomanifest
                        manifest = (
                            f"{self.base_url}/personal/{user}"
                            f"/_api/v2.0/drives/root/items/{item_encoded}/videomanifest"
                        )
                        return manifest
        return None

    def _find_manifest_via_api(self):
        """Busca el manifest via la API de SharePoint."""
        # Intentar obtener info del item via la API de sharing
        encoded_url = base64.urlsafe_b64encode(self.shared_url.encode()).decode().rstrip("=")
        sharing_token = f"u!{encoded_url}"

        api_endpoints = [
            f"{self.base_url}/_api/v2.0/shares/{sharing_token}/driveItem",
            f"{self.base_url}/_api/v2.0/shares/{sharing_token}/root",
        ]

        for endpoint in api_endpoints:
            try:
                resp = self.session.get(
                    endpoint,
                    headers={"Accept": "application/json"},
                    timeout=15,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Buscar download URL o webUrl
                    web_url = data.get("webUrl", "")
                    item_id = data.get("id", "")
                    drive_id = data.get("parentReference", {}).get("driveId", "")

                    if drive_id and item_id:
                        manifest = (
                            f"{self.base_url}/_api/v2.0/drives/{drive_id}"
                            f"/items/{item_id}/videomanifest"
                            f"?part=partitions&format=dash"
                        )
                        test = self.session.get(manifest, timeout=10)
                        if test.status_code == 200:
                            return manifest
            except Exception:
                continue

        return None

    def _parse_manifest(self, mpd_content, manifest_url):
        """Parsea el manifest DASH y extrae información de segmentos."""
        print("  [B.2] Parseando manifest DASH...")

        try:
            # Remover namespace para facilitar el parseo
            mpd_clean = re.sub(r'\sxmlns="[^"]+"', '', mpd_content, count=1)
            root = ET.fromstring(mpd_clean)
        except ET.ParseError as e:
            print(f"    Error parseando XML: {e}")
            # Intentar como texto plano
            return self._parse_manifest_fallback(mpd_content, manifest_url)

        result = {
            "video_segments": [],
            "audio_segments": [],
            "key_url": None,
            "kid": None,
            "iv": None,
        }

        # Buscar BaseURL global
        global_base_url_elem = root.find("{urn:mpeg:DASH:schema:MPD:2011}BaseURL")
        if global_base_url_elem is None:
            global_base_url_elem = root.find("BaseURL")
        
        if global_base_url_elem is not None and global_base_url_elem.text:
            manifest_base = global_base_url_elem.text.strip()
            if not manifest_base.endswith('/'):
                manifest_base += '/'
        else:
            manifest_base = manifest_url.rsplit("/", 1)[0] + "/"

        # Buscar ContentProtection y clave
        for cp in root.iter("ContentProtection"):
            scheme = cp.get("schemeIdUri", "")
            if "aes128" in scheme or "sea" in scheme:
                # Buscar kid e iv
                result["kid"] = cp.get("kid") or cp.get("default_KID")
                for child in cp:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if tag == "CryptoPeriod" or "key" in tag.lower():
                        result["key_url"] = child.get("keyUrlTemplate") or child.get("keyUrl")
                        result["iv"] = child.get("IV") or child.get("iv")

        # Buscar VideoProtectionKey en el manifest completo
        key_match = re.search(r'(https?://[^\s"<>]+VideoProtectionKey[^\s"<>]*)', mpd_content)
        if key_match:
            result["key_url"] = key_match.group(1)

        # También buscar la clave en atributos genéricos
        for elem in root.iter():
            for attr_name, attr_val in elem.attrib.items():
                if "VideoProtectionKey" in str(attr_val):
                    result["key_url"] = attr_val
                if attr_name.lower() == "iv" and attr_val:
                    result["iv"] = attr_val

        # Parsear AdaptationSets
        for adapt_set in root.iter("AdaptationSet"):
            content_type = adapt_set.get("contentType", "").lower()
            mime_type = adapt_set.get("mimeType", "").lower()

            is_video = "video" in content_type or "video" in mime_type
            is_audio = "audio" in content_type or "audio" in mime_type

            # Si no se especifica, inferir del codec
            if not is_video and not is_audio:
                for rep in adapt_set.iter("Representation"):
                    codec = rep.get("codecs", "").lower()
                    if "avc" in codec or "h264" in codec or "hevc" in codec:
                        is_video = True
                    elif "aac" in codec or "mp4a" in codec or "opus" in codec:
                        is_audio = True

            # Seleccionar la mejor representación (mayor bitrate)
            best_rep = None
            best_bw = 0
            for rep in adapt_set.iter("Representation"):
                bw = int(rep.get("bandwidth", "0"))
                if bw >= best_bw:
                    best_bw = bw
                    best_rep = rep

            if best_rep is None:
                continue

            # Extraer segmentos
            segments = self._extract_segments(best_rep, adapt_set, manifest_base, mpd_content)

            if is_video:
                result["video_segments"] = segments
                print(f"    Video: {len(segments)} segmentos, {best_bw/1000:.0f} kbps")
            elif is_audio:
                result["audio_segments"] = segments
                print(f"    Audio: {len(segments)} segmentos, {best_bw/1000:.0f} kbps")

        if not result["video_segments"]:
            print("    ⚠️  No se encontraron segmentos de video en el manifest")
            return None

        return result

    def _extract_segments(self, representation, adapt_set, manifest_base, mpd_content):
        """Extrae las URLs de los segmentos desde una representación DASH."""
        segments = []

        # Método 1: SegmentList
        seg_list = representation.find("SegmentList") or adapt_set.find("SegmentList")
        if seg_list is not None:
            init = seg_list.find("Initialization")
            if init is not None:
                url = init.get("sourceURL") or init.get("range")
                if url:
                    segments.append(urljoin(manifest_base, url))

            for seg_url in seg_list.iter("SegmentURL"):
                media = seg_url.get("media") or seg_url.get("mediaURL")
                if media:
                    segments.append(urljoin(manifest_base, media))
            if segments:
                return segments

        # Método 2: SegmentTemplate
        seg_tmpl = representation.find("SegmentTemplate") or adapt_set.find("SegmentTemplate")
        if seg_tmpl is not None:
            init_tmpl = seg_tmpl.get("initialization")
            media_tmpl = seg_tmpl.get("media")
            timescale = int(seg_tmpl.get("timescale", "1"))
            rep_id = representation.get("id", "0")

            if init_tmpl:
                init_url = init_tmpl.replace("$RepresentationID$", rep_id)
                segments.append(urljoin(manifest_base, init_url))

            # SegmentTimeline
            timeline = seg_tmpl.find("SegmentTimeline")
            if timeline is not None:
                time_pos = 0
                for s_elem in timeline.iter("S"):
                    t = int(s_elem.get("t", str(time_pos)))
                    d = int(s_elem.get("d", "0"))
                    r = int(s_elem.get("r", "0"))

                    for i in range(r + 1):
                        if media_tmpl:
                            seg_url = media_tmpl.replace("$RepresentationID$", rep_id)
                            seg_url = seg_url.replace("$Time$", str(t + i * d))
                            seg_url = seg_url.replace("$Number$", str(len(segments)))
                            segments.append(urljoin(manifest_base, seg_url))
                    time_pos = t + (r + 1) * d
            else:
                # SegmentTemplate con número de segmentos
                start_number = int(seg_tmpl.get("startNumber", "1"))
                duration = int(seg_tmpl.get("duration", "0"))
                if duration > 0 and media_tmpl:
                    # Estimar número de segmentos (4160s de video)
                    total_duration = 4200  # Segundos estimados
                    seg_duration = duration / timescale
                    num_segments = int(total_duration / seg_duration) + 1
                    for i in range(start_number, start_number + num_segments):
                        seg_url = media_tmpl.replace("$RepresentationID$", rep_id)
                        seg_url = seg_url.replace("$Number$", str(i))
                        segments.append(urljoin(manifest_base, seg_url))

            if segments:
                return segments

        # Método 3: BaseURL (un solo segmento grande)
        base_url_elem = representation.find("BaseURL")
        if base_url_elem is not None and base_url_elem.text:
            segments.append(urljoin(manifest_base, base_url_elem.text.strip()))
            return segments

        # Método 4: URLs directas en el manifest (regex fallback)
        rep_id = representation.get("id", "")
        url_pattern = re.compile(
            rf'(https?://[^\s"<>]+(?:segment|chunk|frag)[^\s"<>]*{re.escape(rep_id)}[^\s"<>]*)',
            re.IGNORECASE,
        )
        matches = url_pattern.findall(mpd_content)
        for m in matches:
            segments.append(m)

        return segments

    def _parse_manifest_fallback(self, mpd_content, manifest_url):
        """Parseo de fallback usando regex cuando el XML falla."""
        result = {
            "video_segments": [],
            "audio_segments": [],
            "key_url": None,
            "kid": None,
            "iv": None,
        }

        # Buscar todas las URLs de segmentos
        url_pattern = re.compile(r'(https?://[^\s"<>]+\.(m4s|mp4|ts|fmp4)[^\s"<>]*)', re.IGNORECASE)
        all_urls = url_pattern.findall(mpd_content)

        for url, ext in all_urls:
            if "video" in url.lower():
                result["video_segments"].append(url)
            elif "audio" in url.lower():
                result["audio_segments"].append(url)
            else:
                result["video_segments"].append(url)

        # Buscar clave
        key_match = re.search(r'(https?://[^\s"<>]+VideoProtectionKey[^\s"<>]*)', mpd_content)
        if key_match:
            result["key_url"] = key_match.group(1)

        return result if result["video_segments"] else None

    def _get_decryption_key(self, segments_info):
        """Obtiene la clave de descifrado AES."""
        key_url = segments_info.get("key_url")
        if not key_url:
            return None, None

        try:
            resp = self.session.get(key_url, timeout=15)
            if resp.status_code == 200:
                key = resp.content

                # La IV puede venir del manifest o ser los primeros 16 bytes
                iv_str = segments_info.get("iv")
                if iv_str:
                    # Puede ser hex con prefijo 0x
                    iv_str = iv_str.replace("0x", "").replace("0X", "")
                    iv = bytes.fromhex(iv_str)
                else:
                    # Usar los primeros 16 bytes de la clave como IV (o ceros)
                    iv = b"\x00" * 16

                return key[:16], iv[:16]
        except Exception as e:
            print(f"    Error obteniendo clave: {e}")

        return None, None

    def _download_segments(self, segments, key, iv, temp_dir, label):
        """Descarga y (opcionalmente) descifra los segmentos."""
        if not segments:
            print(f"  Sin segmentos de {label}")
            return None

        print(f"\n  Descargando {len(segments)} segmentos de {label}...")
        output_file = os.path.join(temp_dir, f"{label}_combined.mp4")

        cipher_module = None
        if key:
            try:
                from Crypto.Cipher import AES
                cipher_module = AES
            except ImportError:
                print("    ⚠️  pycryptodome no disponible, descargando sin descifrar")

        downloaded = 0
        total = len(segments)

        with open(output_file, "wb") as out_f:
            for i, seg_url in enumerate(segments):
                try:
                    resp = self.session.get(seg_url, timeout=60)
                    if resp.status_code != 200:
                        print(f"\n    ⚠️  Segmento {i+1} error: {resp.status_code}")
                        if resp.status_code in (401, 403, 429):
                            print(f"        Detalle: {resp.text[:200]}")
                        time.sleep(2) # Backoff
                        continue

                    data = resp.content

                    # Descifrar si tenemos clave
                    if cipher_module and key:
                        try:
                            # Para cada segmento, la IV puede ser diferente
                            # En DASH sea:aes128-cbc, la IV suele ser el índice del segmento
                            seg_iv = iv
                            if iv == b"\x00" * 16:
                                # Usar el índice del segmento como IV
                                seg_iv = struct.pack(">QQ", 0, i)

                            cipher = cipher_module.new(key, cipher_module.MODE_CBC, seg_iv)
                            data = cipher.decrypt(data)

                            # Remover PKCS7 padding del último segmento
                            if i == total - 1 and data:
                                pad_len = data[-1]
                                if 0 < pad_len <= 16:
                                    if all(b == pad_len for b in data[-pad_len:]):
                                        data = data[:-pad_len]
                        except Exception as e:
                            # Si falla el descifrado, guardar tal cual
                            pass

                    out_f.write(data)
                    downloaded += 1
                    progress_bar(downloaded, total, prefix=f"  {label.capitalize()}")
                    time.sleep(0.2) # Pequeño delay para no saturar al servidor

                except requests.exceptions.RequestException as e:
                    print(f"\n    ⚠️  Error descargando segmento {i+1}: {e}")
                    continue

        print()  # Nueva línea

        if downloaded == 0:
            return None

        print(f"    {downloaded}/{total} segmentos descargados")
        return output_file

    def _assemble(self, video_file, audio_file, output_path, temp_dir):
        """Ensambla el video y audio en un archivo MP4 final."""

        # Intentar con ffmpeg primero
        ffmpeg_path = self._find_ffmpeg()

        if ffmpeg_path and audio_file:
            print(f"  Usando ffmpeg: {ffmpeg_path}")
            import subprocess
            cmd = [
                ffmpeg_path, "-y",
                "-i", video_file,
                "-i", audio_file,
                "-c", "copy",
                "-movflags", "+faststart",
                output_path,
            ]
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0 and os.path.exists(output_path):
                    return True
                else:
                    print(f"    ffmpeg error: {result.stderr[:200]}")
            except Exception as e:
                print(f"    ffmpeg error: {e}")

        # Fallback: concatenación directa (sin muxing)
        print("  Usando concatenación directa (sin ffmpeg)...")
        import shutil

        if audio_file and os.path.exists(audio_file):
            # Si hay audio separado, concatenar video + audio en orden
            with open(output_path, "wb") as out:
                with open(video_file, "rb") as vf:
                    shutil.copyfileobj(vf, out)
            print("    ⚠️  Audio no mezclado (se necesita ffmpeg para muxing)")
        else:
            shutil.copy2(video_file, output_path)

        return os.path.exists(output_path) and os.path.getsize(output_path) > 0

    def _find_ffmpeg(self):
        """Busca ffmpeg en el sistema."""
        import shutil
        path = shutil.which("ffmpeg")
        if path:
            return path

        # Buscar en ubicaciones comunes de Windows
        common_paths = [
            r"C:\ffmpeg\bin\ffmpeg.exe",
            r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
            os.path.join(os.path.dirname(__file__), "ffmpeg.exe"),
            os.path.join(os.path.dirname(__file__), "ffmpeg", "bin", "ffmpeg.exe"),
        ]
        for p in common_paths:
            if os.path.exists(p):
                return p

        return None


# ---------------------------------------------------------------------------
# Orquestador principal
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Descargador de video SharePoint protegido con contraseña"
    )
    parser.add_argument("--url", required=True, help="URL del enlace compartido")
    parser.add_argument("--password", required=True, help="Contraseña del enlace")
    parser.add_argument(
        "--output",
        default=None,
        help="Ruta de salida del archivo MP4 (default: fecha_video_sharepoint.mp4)",
    )
    parser.add_argument(
        "--headers-file",
        default=None,
        help="Archivo con headers capturados del navegador (formato JSON)",
    )
    parser.add_argument(
        "--strategy",
        choices=["auto", "direct", "dash"],
        default="auto",
        help="Estrategia de descarga (default: auto)",
    )
    parser.add_argument(
        "--manifest-url",
        default=None,
        help="URL directa del manifiesto DASH (.mpd)",
    )
    args = parser.parse_args()

    # Ruta de salida por defecto
    if not args.output:
        from datetime import date
        today = date.today().isoformat()
        args.output = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"{today}_video_sharepoint.mp4",
        )

    output_path = os.path.abspath(args.output)

    print("=" * 60)
    print("  DESCARGADOR DE VIDEO SHAREPOINT")
    print("=" * 60)
    print(f"  URL:      {args.url[:60]}...")
    print(f"  Salida:   {output_path}")
    print(f"  Estrategia: {args.strategy}")
    print("=" * 60)

    # Fase 1: Autenticación
    auth = SharePointAuth(args.url, args.password)

    # Si se proporcionaron headers manuales, cargarlos
    if args.headers_file and os.path.exists(args.headers_file):
        print("\n  Cargando headers desde archivo...")
        with open(args.headers_file, "r") as f:
            custom_headers = json.load(f)
        auth.session.headers.update(custom_headers.get("headers", {}))
        for name, value in custom_headers.get("cookies", {}).items():
            auth.session.cookies.set(name, value)
        auth.authenticated = True
        print("  ✅ Headers cargados")
    else:
        if not auth.authenticate():
            print("\n" + "=" * 60)
            print("  ⚠️  AUTENTICACIÓN PROGRAMÁTICA FALLÓ")
            print("=" * 60)
            print("  Necesitas capturar los headers desde tu navegador.")
            print("  Instrucciones:")
            print("  1. Abre F12 → pestaña Red/Network")
            print("  2. Navega a la URL del video e ingresa la contraseña")
            print("  3. Busca una petición a 'videomanifest' o al video")
            print("  4. Clic derecho → 'Copiar como cURL'")
            print("  5. Ejecuta este script con --headers-file headers.json")
            print("=" * 60)
            sys.exit(1)

    # Estrategia A: Descarga directa
    success = False
    if args.strategy in ("auto", "direct"):
        downloader = DirectDownloader(
            auth.session, args.url, auth.base_url
        )
        success = downloader.try_download(output_path)

    # Estrategia B: DASH
    if not success and args.strategy in ("auto", "dash"):
        dash = DashDownloader(
            auth.session, args.url, auth.base_url
        )
        success = dash.try_download(output_path, forced_manifest_url=args.manifest_url)

    if success and os.path.exists(output_path) and os.path.getsize(output_path) > 0:
        verify_mp4(output_path)
        print("✅ Descarga completada exitosamente!")
    else:
        print("\n❌ No se pudo descargar el video.")
        print("   Intenta capturar los headers del navegador y usar --headers-file")
        sys.exit(1)


if __name__ == "__main__":
    main()
