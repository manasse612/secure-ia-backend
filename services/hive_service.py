# === Service Hive AI ===
# Intégration avec l'API Hive AI pour la détection de contenu généré par IA et deepfakes
# Endpoint : https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection
# Supporte : images (jpg, png, webp, gif) et vidéos (mp4, webm, m4v)

import httpx
import mimetypes
import logging
from typing import Optional

from config import settings
from services.api_client import hive_api_call, mask_api_key, CircuitBreakerOpen

logger = logging.getLogger(__name__)

# URL de l'API Hive AI v3 (Playground)
HIVE_API_URL = "https://api.thehive.ai/api/v3/hive/ai-generated-and-deepfake-content-detection"


async def hive_detect(
    media_url: Optional[str] = None,
    media_bytes: Optional[bytes] = None,
    filename: Optional[str] = None,
) -> dict:
    """
    Appeler l'API Hive AI pour détecter le contenu généré par IA et les deepfakes.

    Paramètres :
    - media_url : URL publique de l'image ou de la vidéo
    - media_bytes : contenu binaire du fichier (si upload)
    - filename : nom du fichier (pour multipart upload)

    Retourne un dict normalisé avec les scores de détection.
    """
    if not settings.hive_api_key:
        raise RuntimeError(
            "HIVE_API_KEY non configurée. "
            "Veuillez ajouter votre clé API Hive dans le fichier .env."
        )

    logger.info(f"[Hive AI] Détection demandée - URL: {media_url is not None}, Bytes: {media_bytes is not None}")

    headers = {
        "authorization": f"Bearer {settings.hive_api_key}",
    }

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            if media_bytes:
                # Deviner le type MIME à partir du nom de fichier
                content_type = None
                if filename:
                    content_type, _ = mimetypes.guess_type(filename)
                if not content_type:
                    content_type = "application/octet-stream"

                logger.debug(f"[Hive AI] Upload multipart - filename: {filename}, content-type: {content_type}")

                # Upload multipart pour les fichiers locaux avec retry
                async def _upload_bytes():
                    resp = await client.post(
                        HIVE_API_URL,
                        headers=headers,
                        files={"media": (filename or "media_file", media_bytes, content_type)},
                    )
                    resp.raise_for_status()
                    return resp

                response = await hive_api_call(client, "POST", HIVE_API_URL, 
                    files={"media": (filename or "media_file", media_bytes, content_type)},
                    headers=headers)

            elif media_url:
                # Essayer d'abord de télécharger le contenu localement si l'URL est accessible
                # Cela permet de gérer les URLs temporaires (TikTok, etc.) qui expirent rapidement
                downloaded_bytes = None
                try:
                    logger.debug(f"[Hive AI] Tentative de téléchargement de l'URL: {media_url}")
                    download_resp = await client.get(media_url, follow_redirects=True, timeout=30)
                    if download_resp.status_code == 200 and len(download_resp.content) > 0:
                        downloaded_bytes = download_resp.content
                        content_type = download_resp.headers.get('content-type', 'application/octet-stream')
                        logger.info(f"[Hive AI] URL téléchargée: {len(downloaded_bytes)} octets, Content-Type: {content_type}")
                except Exception as e:
                    logger.warning(f"[Hive AI] Impossible de télécharger l'URL: {e}")
                    downloaded_bytes = None
                
                if downloaded_bytes:
                    # Envoyer le contenu téléchargé comme multipart
                    logger.info(f"[Hive AI] Envoi par multipart (contenu téléchargé): {len(downloaded_bytes)} octets")
                    response = await hive_api_call(
                        client, "POST", HIVE_API_URL,
                        headers={"authorization": f"Bearer {settings.hive_api_key}"},
                        files={"media": (filename or "media_file", downloaded_bytes, content_type or "application/octet-stream")},
                    )
                else:
                    # Envoi par URL publique (JSON) - fallback
                    headers["Content-Type"] = "application/json"
                    logger.debug(f"[Hive AI] Envoi par URL (fallback): {media_url}")

                    response = await hive_api_call(
                        client, "POST", HIVE_API_URL,
                        headers=headers,
                        json={
                            "media_metadata": True,
                            "input": [{"media_url": media_url}],
                        }
                    )
            else:
                raise ValueError("Aucun média fourni (ni URL ni fichier)")

            raw = response.json()
            result = _parse_hive_response(raw)
            logger.info(f"[Hive AI] Détection terminée - AI: {result.get('ai_generated_probability', 0):.2%}, Deepfake: {result.get('deepfake_probability', 0):.2%}")
            return result

    except CircuitBreakerOpen:
        logger.error("[Hive AI] Circuit breaker ouvert - service temporairement indisponible")
        return {
            "error": (
                "Le service Hive AI est temporairement indisponible suite à trop d'erreurs. "
                "Veuillez réessayer dans quelques minutes."
            ),
            "circuit_breaker_open": True,
        }
    except httpx.TimeoutException:
        logger.error("[Hive AI] Timeout lors de l'appel API")
        return {"error": "Timeout lors de l'appel à l'API Hive AI (>120s). Le fichier est peut-être trop volumineux."}
    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        logger.error(f"[Hive AI] Erreur HTTP {status_code}: {e.response.text[:200]}")
        
        # Traduire les erreurs Hive courantes en messages clairs
        if status_code == 400:
            return {
                "error": (
                    "Le fichier n'a pas pu être traité. "
                    "Causes possibles : \n"
                    "• Lien temporaire expiré (TikTok, Instagram, etc.)\n"
                    "• Vidéo trop longue (max 60 secondes)\n"
                    "• Fichier trop volumineux (max 200 Mo)\n"
                    "• Format non supporté ou fichier corrompu\n"
                    "• Accès protégé ou géo-bloqué\n\n"
                    "💡 Conseil : Téléchargez la vidéo et uploadez-la directement."
                ),
                "raw_status": status_code,
            }
        elif status_code == 401:
            return {
                "error": "Clé API Hive invalide ou expirée. Vérifiez votre configuration.",
                "raw_status": status_code,
            }
        elif status_code == 429:
            return {
                "error": "Limite de requêtes Hive AI atteinte. Veuillez réessayer dans quelques minutes.",
                "raw_status": status_code,
            }
        return {
            "error": f"Erreur API Hive ({status_code}): {e.response.text[:500]}",
            "raw_status": status_code,
        }
    except Exception as e:
        logger.exception("[Hive AI] Erreur inattendue")
        return {"error": f"Erreur de connexion Hive AI : {str(e)}"}


def _parse_hive_response(raw: dict) -> dict:
    """
    Parser la réponse brute de Hive AI et extraire les scores pertinents.

    Structure attendue de Hive :
    - output[].classes[] avec class/value pairs
    - Classes importantes : ai_generated, not_ai_generated, deepfake,
      ai_generated_audio, not_ai_generated_audio, midjourney, stablediffusion, etc.
    """
    result = {
        "raw": raw,
        "ai_generated_probability": 0.0,
        "not_ai_generated_probability": 0.0,
        "deepfake_probability": 0.0,
        "ai_audio_probability": 0.0,
        "generator_attribution": {},
        "frames": [],
    }

    # Extraire les outputs (peut être multi-frame pour les vidéos)
    outputs = raw.get("output", [])
    if not outputs:
        # Certaines réponses Hive encapsulent dans status[].response.output
        statuses = raw.get("status", [])
        for s in statuses:
            resp = s.get("response", {})
            outputs = resp.get("output", [])
            if outputs:
                break

    if not outputs:
        result["error"] = "Aucun résultat dans la réponse Hive"
        return result

    # Générateurs IA connus
    generator_classes = {
        "midjourney", "stablediffusion", "dalle", "flux",
        "other_image_generators", "none",
    }

    all_ai_scores = []
    all_deepfake_scores = []
    all_audio_scores = []

    for frame in outputs:
        classes = frame.get("classes", [])
        extra = frame.get("extra", [])

        # Extraire frame_index et timestamp
        frame_index = 0
        timestamp = 0.0
        for e in extra:
            if e.get("name") == "frame_index":
                frame_index = e.get("value", 0)
            elif e.get("name") == "timestamp":
                timestamp = e.get("value", 0.0)

        frame_data = {
            "frame_index": frame_index,
            "timestamp": timestamp,
            "scores": {},
        }

        for cls in classes:
            class_name = cls.get("class", "")
            value = cls.get("value", 0.0)

            if class_name == "ai_generated":
                frame_data["scores"]["ai_generated"] = value
                all_ai_scores.append(value)
            elif class_name == "not_ai_generated":
                frame_data["scores"]["not_ai_generated"] = value
            elif class_name == "deepfake":
                frame_data["scores"]["deepfake"] = value
                all_deepfake_scores.append(value)
            elif class_name == "ai_generated_audio":
                frame_data["scores"]["ai_generated_audio"] = value
                all_audio_scores.append(value)
            elif class_name == "not_ai_generated_audio":
                frame_data["scores"]["not_ai_generated_audio"] = value
            elif class_name in generator_classes:
                if value > 0.01:
                    result["generator_attribution"][class_name] = max(
                        result["generator_attribution"].get(class_name, 0), value
                    )

        result["frames"].append(frame_data)

    # Agréger les scores (max sur toutes les frames, comme recommandé par Hive)
    if all_ai_scores:
        result["ai_generated_probability"] = round(max(all_ai_scores), 4)
        result["not_ai_generated_probability"] = round(1 - max(all_ai_scores), 4)
    if all_deepfake_scores:
        result["deepfake_probability"] = round(max(all_deepfake_scores), 4)
    if all_audio_scores:
        result["ai_audio_probability"] = round(max(all_audio_scores), 4)

    # Nombre total de frames analysées
    result["total_frames"] = len(outputs)

    # Retirer le champ raw pour ne pas surcharger la réponse (garder dans les détails si besoin)
    del result["raw"]

    return result
