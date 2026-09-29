#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Descargador de alta velocidad para videos de SharePoint / Stream vía HLS.
Con descifrado AES-128-CBC integrado, descarga paralela y muxing ffmpeg.

Estructura HLS de SharePoint Media Service:
  - Master playlist define commonVpkUrlVariable (URL de VideoProtectionKey)
  - Sub-playlists importan esa variable via IMPORT
  - El primer segmento NO está cifrado
  - A partir del #EXT-X-KEY, todos los siguientes sí lo están (AES-128-CBC)
"""

import os
import re
import sys
import json
import time
import subprocess
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES

# Fix para terminales Windows cp1252 que no soportan emojis/unicode
import io
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ──────────────────────────────────────────────────────────────
#  Utilidades
# ──────────────────────────────────────────────────────────────

def progress_bar(current, total, prefix="Progreso", length=40):
    pct = current / total if total > 0 else 0
    filled = int(length * pct)
    bar = "█" * filled + "░" * (length - filled)
    sys.stdout.write(f"\r{prefix} [{bar}] {pct*100:5.1f}% ({current}/{total})")
    sys.stdout.flush()

def unpad_pkcs7(data):
    """Elimina el padding PKCS7 del ÚLTIMO bloque descifrado."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]

def download_bytes(url, headers, session=None, retries=4):
    """Descarga bytes de una URL con reintentos."""
    s = session or requests
    for attempt in range(retries):
        try:
            r = s.get(url, headers=headers, timeout=60)
            if r.status_code == 200:
                return r.content
            elif r.status_code in (429, 503):
                time.sleep(2 + attempt * 3)
            else:
                print(f"\n  ⚠ HTTP {r.status_code} en {url[:60]}... (intento {attempt+1})")
                time.sleep(1 + attempt)
        except Exception as e:
            print(f"\n  ⚠ Error de red: {e} (intento {attempt+1})")
            time.sleep(2 + attempt)
    raise RuntimeError(f"Fallo al descargar tras {retries} intentos: {url[:80]}...")

# ──────────────────────────────────────────────────────────────
#  Parser HLS  (con soporte de variables del master)
# ──────────────────────────────────────────────────────────────

def parse_master_playlist(session, master_url, headers):
    """
    Parsea el master playlist HLS y extrae:
      - video_playlist_url
      - audio_playlist_url
      - common_vpk_url: la URL de VideoProtectionKey
    """
    r = session.get(master_url, headers=headers, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Error {r.status_code} al obtener master HLS")

    video_url = None
    audio_url = None
    common_vpk_url = ""

    for line in r.text.splitlines():
        line = line.strip()

        # Variable global VPK definida en el master
        if 'NAME="commonVpkUrlVariable"' in line:
            m = re.search(r'VALUE="([^"]*)"', line)
            if m:
                common_vpk_url = m.group(1)

        # Video sub-playlist URL
        if line.startswith("https://") and "track=video" in line and not video_url:
            video_url = line

        # Audio sub-playlist URL
        if "TYPE=AUDIO" in line and 'URI="' in line and not audio_url:
            audio_url = line.split('URI="')[1].split('"')[0]

    return {
        "video_url": video_url,
        "audio_url": audio_url,
        "common_vpk_url": common_vpk_url,
    }


def parse_sub_playlist(session, playlist_url, headers, common_vpk_url=""):
    """
    Parsea una sub-playlist HLS extrayendo:
      - init_url: URL del segmento de inicialización
      - segments: lista de dicts con {url, encrypted}
      - key_url: URL para obtener la clave AES (si hay cifrado)
      - iv: bytes del IV (16 bytes)

    El primer segmento (antes del #EXT-X-KEY) no está cifrado.
    Los segmentos después del #EXT-X-KEY sí lo están.
    """
    r = session.get(playlist_url, headers=headers, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Error {r.status_code} al obtener playlist: {playlist_url[:80]}")

    common_url = ""
    init_url = None
    segments = []
    key_url = None
    iv_bytes = None
    encryption_active = False  # Se activa cuando encontramos #EXT-X-KEY

    for line in r.text.splitlines():
        line = line.strip()

        # Variable de sustitución local
        if 'NAME="commonUrlVariable"' in line:
            m = re.search(r'VALUE="([^"]*)"', line)
            if m:
                common_url = m.group(1)

        # Init segment (siempre sin cifrar)
        if '#EXT-X-MAP:URI="' in line:
            init_url = line.split('#EXT-X-MAP:URI="')[1].split('"')[0]

        # Tag de cifrado - activa el cifrado para segmentos siguientes
        if line.startswith('#EXT-X-KEY:') and 'METHOD=AES-128' in line:
            encryption_active = True
            m_uri = re.search(r'URI="([^"]+)"', line)
            m_iv = re.search(r'IV=0x([0-9a-fA-F]+)', line)
            if m_uri:
                raw = m_uri.group(1)
                raw = raw.replace("{$commonVpkUrlVariable}", common_vpk_url)
                raw = raw.replace("{$commonUrlVariable}", common_url)
                key_url = raw
            if m_iv:
                iv_bytes = bytes.fromhex(m_iv.group(1))

        # Segmentos media
        if line.startswith("https://"):
            full_url = line.replace("{$commonUrlVariable}", common_url)
            full_url = full_url.replace("{$commonVpkUrlVariable}", common_vpk_url)
            segments.append({
                "url": full_url,
                "encrypted": encryption_active,
            })

    return {
        "init_url": init_url,
        "segments": segments,
        "key_url": key_url,
        "iv": iv_bytes,
    }

# ──────────────────────────────────────────────────────────────
#  Descarga + descifrado de stream
# ──────────────────────────────────────────────────────────────

def download_and_decrypt_stream(session, stream_info, headers, output_file, label="Stream", max_workers=8):
    """
    Descarga todos los segmentos en paralelo, descifra los que
    están marcados como cifrados, y ensambla el archivo final.
    """
    init_url = stream_info["init_url"]
    segments = stream_info["segments"]
    key_url = stream_info["key_url"]
    iv = stream_info["iv"]
    total = len(segments)

    encrypted_count = sum(1 for s in segments if s["encrypted"])
    plain_count = total - encrypted_count

    print(f"\n[{label}] {total} segmentos ({plain_count} sin cifrar, {encrypted_count} cifrados)")

    # 1. Obtener clave AES
    aes_key = None
    if key_url and encrypted_count > 0:
        print(f"  🔑 Obteniendo clave AES... ", end="")
        aes_key = download_bytes(key_url, headers, session)
        print(f"OK ({len(aes_key)} bytes)")
    else:
        print(f"  ℹ  Sin cifrado detectado.")

    # 2. Init segment (no cifrado)
    print(f"  📦 Descargando init segment... ", end="")
    init_data = download_bytes(init_url, headers, session)
    print(f"OK ({len(init_data)} bytes)")

    # 3. Descarga paralela de segmentos media
    print(f"  ⬇  Descargando {total} segmentos ({max_workers} hilos)...")
    results = {}
    completed = 0
    errors = 0
    progress_bar(0, total, prefix=f"  {label}")

    segment_urls = [s["url"] for s in segments]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx = {
            executor.submit(download_bytes, url, headers, session): i
            for i, url in enumerate(segment_urls)
        }

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                data = future.result()
                results[idx] = data
                completed += 1
                progress_bar(completed, total, prefix=f"  {label}")
            except Exception as e:
                errors += 1
                print(f"\n  ❌ Error en segmento {idx}: {e}")
                if errors > 10:
                    raise RuntimeError("Demasiados errores de descarga, abortando.")

    print()  # nueva línea

    if len(results) < total:
        print(f"  ⚠ Solo se descargaron {len(results)}/{total} segmentos.")

    # 4. Descifrar y ensamblar
    print(f"  🔓 Descifrando y ensamblando...")
    with open(output_file, "wb") as f:
        f.write(init_data)
        for i in range(total):
            if i not in results:
                print(f"  ⚠ Segmento {i} faltante, saltando...")
                continue

            seg_data = results[i]

            if segments[i]["encrypted"] and aes_key and iv:
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                seg_data = cipher.decrypt(seg_data)
                seg_data = unpad_pkcs7(seg_data)

            f.write(seg_data)

    size_mb = os.path.getsize(output_file) / (1024 * 1024)
    print(f"  ✅ {label} completado: {size_mb:.2f} MB → {os.path.basename(output_file)}")

# ──────────────────────────────────────────────────────────────
#  Main
# ──────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  DESCARGADOR SHAREPOINT / STREAM  (HLS + AES-128)")
    print("=" * 60)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    headers_file = os.path.join(script_dir, "headers.json")
    ffmpeg_exe = os.path.join(script_dir, "ffmpeg.exe")
    final_output = os.path.join(script_dir, "2026-09-28_video_sharepoint.mp4")

    # ── Headers ────────────────────────────────────────────────
    if not os.path.exists(headers_file):
        print(f"❌ Error: {headers_file} no encontrado.")
        sys.exit(1)

    with open(headers_file, "r", encoding="utf-8") as f:
        headers_data = json.load(f)
    headers = headers_data.get("headers", {})

    if "x-spopactoken" not in headers:
        print("❌ Error: 'x-spopactoken' no encontrado en headers.json")
        sys.exit(1)

    import argparse
    parser = argparse.ArgumentParser(description="Descargador HLS SharePoint / Stream")
    parser.add_argument("--manifest-url", help="URL maestra del manifiesto HLS (videomanifest)", default=None)
    parser.add_argument("--output", help="Ruta de salida del archivo MP4 final", default=os.path.join(script_dir, "2026-09-28_video_sharepoint.mp4"))
    args, unknown = parser.parse_known_args()

    hls_master_url = args.manifest_url
    if not hls_master_url:
        print("\n[?] No se especificó --manifest-url.")
        hls_master_url = input("Ingresa la URL maestra HLS (videomanifest): ").strip()
    
    if not hls_master_url:
        print("❌ Error: La URL maestra HLS es obligatoria.")
        sys.exit(1)

    final_output = args.output

    session = requests.Session()

    # ── Paso 1: Master playlist ───────────────────────────────
    print("\n[Paso 1] Obteniendo master playlist HLS...")
    master_info = parse_master_playlist(session, hls_master_url, headers)

    if not master_info["video_url"]:
        print("❌ No se encontró la playlist de video en el master.")
        sys.exit(1)
    if not master_info["audio_url"]:
        print("❌ No se encontró la playlist de audio en el master.")
        sys.exit(1)

    common_vpk = master_info["common_vpk_url"]
    print(f"  ✅ Playlists de video y audio identificadas.")
    print(f"  🔑 VPK URL: {common_vpk[:60]}...")

    # ── Paso 2: Parsear sub-playlists ─────────────────────────
    print("\n[Paso 2] Parseando playlist de video...")
    video_info = parse_sub_playlist(session, master_info["video_url"], headers, common_vpk)
    v_enc = sum(1 for s in video_info["segments"] if s["encrypted"])
    v_plain = len(video_info["segments"]) - v_enc
    print(f"  Segmentos de video: {len(video_info['segments'])} ({v_plain} plain + {v_enc} cifrados)")
    print(f"  Key URL: {'SI' if video_info['key_url'] else 'NO'}")
    print(f"  IV: {'SI' if video_info['iv'] else 'NO'}")

    print("\n[Paso 3] Parseando playlist de audio...")
    audio_info = parse_sub_playlist(session, master_info["audio_url"], headers, common_vpk)
    a_enc = sum(1 for s in audio_info["segments"] if s["encrypted"])
    a_plain = len(audio_info["segments"]) - a_enc
    print(f"  Segmentos de audio: {len(audio_info['segments'])} ({a_plain} plain + {a_enc} cifrados)")
    print(f"  Key URL: {'SI' if audio_info['key_url'] else 'NO'}")
    print(f"  IV: {'SI' if audio_info['iv'] else 'NO'}")

    # ── Paso 3: Descargar + descifrar ─────────────────────────
    temp_video = os.path.join(script_dir, "temp_video.mp4")
    temp_audio = os.path.join(script_dir, "temp_audio.mp4")

    t0 = time.time()

    print("\n[Paso 4] Descargando y descifrando video...")
    download_and_decrypt_stream(session, video_info, headers, temp_video, label="Video 1080p", max_workers=16)

    print("\n[Paso 5] Descargando y descifrando audio...")
    download_and_decrypt_stream(session, audio_info, headers, temp_audio, label="Audio AAC", max_workers=16)

    t_download = time.time() - t0
    print(f"\n⚡ Descarga y descifrado completados en {t_download:.1f} segundos.")

    # ── Verificar temporales con ffmpeg ───────────────────────
    if not os.path.exists(ffmpeg_exe):
        ffmpeg_exe_path = "ffmpeg"
    else:
        ffmpeg_exe_path = ffmpeg_exe

    print("\n[Paso 6] Verificando archivos temporales...")
    for label, temp_file in [("Video", temp_video), ("Audio", temp_audio)]:
        probe = subprocess.run(
            [ffmpeg_exe_path, "-i", temp_file],
            capture_output=True, text=True
        )
        for ln in probe.stderr.splitlines():
            if "Duration:" in ln:
                print(f"  {label}: {ln.strip()}")
                break

    # ── Paso 7: Muxing con ffmpeg ─────────────────────────────
    print("\n[Paso 7] Uniendo video y audio con ffmpeg...")

    cmd = [
        ffmpeg_exe_path,
        "-y",
        "-i", temp_video,
        "-i", temp_audio,
        "-c", "copy",
        "-movflags", "+faststart",
        final_output
    ]

    print(f"  Ejecutando: {' '.join(cmd[:6])} ...")
    res = subprocess.run(cmd, capture_output=True, text=True)

    if res.returncode != 0:
        print(f"❌ Error en ffmpeg (código {res.returncode}):")
        print(f"  {res.stderr[-500:]}")
        print(f"  Archivos temporales conservados:")
        print(f"    {temp_video}")
        print(f"    {temp_audio}")
        sys.exit(1)

    # ── Limpieza ──────────────────────────────────────────────
    try:
        if os.path.exists(temp_video):
            os.remove(temp_video)
        if os.path.exists(temp_audio):
            os.remove(temp_audio)
    except Exception:
        pass

    # ── Resultado ─────────────────────────────────────────────
    final_size_mb = os.path.getsize(final_output) / (1024 * 1024)
    probe_res = subprocess.run(
        [ffmpeg_exe_path, "-i", final_output],
        capture_output=True, text=True
    )
    duration = "desconocida"
    for ln in probe_res.stderr.splitlines():
        if "Duration:" in ln:
            duration = ln.strip()
            break

    print("\n" + "=" * 60)
    print("  🎉 ¡DESCARGA COMPLETADA CON ÉXITO!")
    print("=" * 60)
    print(f"  Archivo:   {final_output}")
    print(f"  Tamaño:    {final_size_mb:.2f} MB")
    print(f"  {duration}")
    print("=" * 60)

if __name__ == "__main__":
    main()
