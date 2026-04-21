# === Service d'analyse d'images ===
# Détecte si une image est générée par IA, manipulée, ou authentique
# Utilise l'API Hive AI pour la détection de deepfakes et contenu IA
# Extrait les métadonnées EXIF de l'image

import time
import httpx
from typing import Optional
from datetime import datetime

from config import settings


# === Fonction de nettoyage pour PostgreSQL (AJOUTÉE) ===
def clean_metadata_for_postgresql(data):
    """
    Nettoie récursivement toutes les chaînes d'un dictionnaire
    pour enlever les caractères null (\u0000) qui font planter PostgreSQL.
    """
    if isinstance(data, dict):
        return {k: clean_metadata_for_postgresql(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [clean_metadata_for_postgresql(item) for item in data]
    elif isinstance(data, str):
        # Remplacer les caractères null par un espace
        return data.replace('\x00', ' ').replace('\u0000', ' ')
    else:
        return data


async def analyze_image(image_url: Optional[str] = None, image_bytes: Optional[bytes] = None, filename: Optional[str] = None) -> dict:
    """
    Analyser une image pour détecter les manipulations et l'IA.
    
    Étapes :
    1. Extraire les métadonnées de l'image (EXIF)
    2. Appeler l'API Hive AI pour la détection deepfake
    3. Calculer un score d'authenticité global
    4. Générer un résumé en langage naturel
    
    Paramètres :
    - image_url : URL de l'image à analyser
    - image_bytes : contenu binaire de l'image (si upload)
    
    Retourne un dictionnaire avec les résultats détaillés.
    """
    start_time = time.time()
    results = {
        "metadata": {},
        "ai_detection": {},
        "manipulation_detection": {},
        "score": 0.0,
        "verdict": "non_verifiable",
        "summary": "",
    }

    # --- Étape 1 : Extraction des métadonnées ---
    try:
        metadata = await _extract_metadata(image_url, image_bytes)
        results["metadata"] = metadata
    except Exception as e:
        results["metadata"] = {"error": str(e)}

    # --- Étape 2 : Détection IA via Hive AI API ---
    try:
        ai_result = await _detect_ai_generated(image_url, image_bytes, filename)
        results["ai_detection"] = ai_result
    except RuntimeError as e:
        # Configuration error - on propage l'erreur pour bloquer l'analyse
        raise RuntimeError(f"Service d'analyse indisponible : {str(e)}")
    except Exception as e:
        results["ai_detection"] = {"error": str(e)}

    # --- Étape 3 : Vérifier si la détection a échoué ---
    if results["ai_detection"].get("error"):
        raise RuntimeError(f"Analyse impossible : {results['ai_detection']['error']}")

    # --- Étape 4 : Calcul du score d'authenticité ---
    score = _calculate_authenticity_score(results)
    results["score"] = score

    # --- Étape 4 : Déterminer le verdict ---
    if score >= 70:
        results["verdict"] = "authentique"
    elif score >= 40:
        results["verdict"] = "suspect"
    else:
        results["verdict"] = "deepfake"

    # --- Étape 5 : Générer le résumé ---
    results["summary"] = _generate_summary(results)

    # Temps de traitement
    results["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)

    # === NETTOYAGE FINAL POUR POSTGRESQL (AJOUTÉ) ===
    results = clean_metadata_for_postgresql(results)

    return results


async def _extract_metadata(image_url: Optional[str], image_bytes: Optional[bytes]) -> dict:
    """
    Extraire les métadonnées EXIF d'une image.
    - Date de création, appareil photo, GPS, logiciel d'édition
    - Permet de détecter si l'image a été modifiée
    """
    metadata = {
        "has_exif": False,
        "camera": None,
        "date_taken": None,
        "software": None,
        "gps": None,
        "dimensions": None,
    }

    try:
        # Télécharger l'image si URL fournie
        if image_url and not image_bytes:
            async with httpx.AsyncClient() as client:
                response = await client.get(image_url, timeout=10)
                image_bytes = response.content

        if image_bytes:
            # Utiliser Pillow pour extraire les métadonnées
            from PIL import Image
            from PIL.ExifTags import TAGS
            import io

            img = Image.open(io.BytesIO(image_bytes))
            metadata["dimensions"] = {"width": img.width, "height": img.height}
            metadata["format"] = img.format

            # Extraire les données EXIF
            exif_data = img._getexif()
            if exif_data:
                metadata["has_exif"] = True
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, tag_id)
                    if tag_name == "Make":
                        metadata["camera"] = str(value)
                    elif tag_name == "DateTime":
                        metadata["date_taken"] = str(value)
                    elif tag_name == "Software":
                        metadata["software"] = str(value)

    except Exception as e:
        metadata["error"] = f"Erreur lors de l'extraction : {str(e)}"

    return metadata


async def _detect_ai_generated(image_url: Optional[str], image_bytes: Optional[bytes], filename: Optional[str] = None) -> dict:
    """
    Détecter si l'image est générée par IA via l'API Hive AI.
    Retourne un score de probabilité de génération IA.
    """
    if not settings.hive_api_key:
        raise RuntimeError(
            "HIVE_API_KEY non configurée. "
            "Veuillez configurer la clé API Hive dans le fichier .env"
        )

    # Appel réel à l'API Hive AI
    from services.hive_service import hive_detect

    hive_result = await hive_detect(
        media_url=image_url,
        media_bytes=image_bytes,
        filename=filename or "image.jpg",
    )

    if "error" in hive_result:
        return hive_result

    # Normaliser la réponse Hive vers le format attendu par le reste du service
    ai_prob = hive_result.get("ai_generated_probability", 0)
    deepfake_prob = hive_result.get("deepfake_probability", 0)
    generators = hive_result.get("generator_attribution", {})

    # Déterminer le générateur le plus probable
    model_detected = None
    if generators:
        top_gen = max(generators.items(), key=lambda x: x[1])
        if top_gen[0] != "none" and top_gen[1] > 0.1:
            model_detected = top_gen[0]

    return {
        "mode": "production",
        "provider": "hive_ai",
        "ai_generated_probability": round(ai_prob, 4),
        "deepfake_probability": round(deepfake_prob, 4),
        "model_detected": model_detected,
        "generator_scores": generators,
        "confidence": round(max(ai_prob, 1 - ai_prob), 4),
        "total_frames": hive_result.get("total_frames", 1),
    }


def _calculate_authenticity_score(results: dict) -> float:
    """
    Calculer le score d'authenticité global de l'image (0 à 100).
    - 100 = image très probablement authentique
    - 0 = image très probablement manipulée ou générée par IA
    """
    score = 100.0

    # Pénalité si l'image est probablement générée par IA
    ai_detection = results.get("ai_detection", {})
    ai_prob = ai_detection.get("ai_generated_probability", 0)
    score -= ai_prob * 60  # Jusqu'à -60 points

    # Bonus si l'image a des métadonnées EXIF (plus probable d'être authentique)
    metadata = results.get("metadata", {})
    if metadata.get("has_exif"):
        score += 10
    else:
        score -= 10

    # Pénalité si un logiciel d'édition est détecté
    if metadata.get("software"):
        software = metadata["software"].lower()
        if any(tool in software for tool in ["photoshop", "gimp", "lightroom"]):
            score -= 15

    # Limiter le score entre 0 et 100
    return round(max(0, min(100, score)), 1)


def _generate_summary(results: dict) -> str:
    """
    Générer un résumé en français de l'analyse de l'image.
    Explique de manière claire les résultats pour l'utilisateur.
    """
    score = results.get("score", 0)
    verdict = results.get("verdict", "non_verifiable")
    ai_detection = results.get("ai_detection", {})
    metadata = results.get("metadata", {})

    # Construire le résumé
    lines = []

    if verdict == "authentique":
        lines.append("✅ Cette image semble authentique.")
    elif verdict == "suspect":
        lines.append("⚠️ Cette image présente des éléments suspects.")
    else:
        lines.append("❌ Cette image est probablement un deepfake ou générée par IA.")

    lines.append(f"Score d'authenticité : {score}/100")

    # Détails sur la détection IA
    ai_prob = ai_detection.get("ai_generated_probability", 0)
    if ai_prob > 0.7:
        lines.append(f"Forte probabilité de génération par IA ({int(ai_prob*100)}%)")
    elif ai_prob > 0.4:
        lines.append(f"Probabilité modérée de génération par IA ({int(ai_prob*100)}%)")

    # Détails sur les métadonnées
    if metadata.get("has_exif"):
        lines.append("Métadonnées EXIF présentes (bon signe d'authenticité)")
        if metadata.get("camera"):
            # Nettoyage supplémentaire pour le résumé (au cas où)
            camera = metadata['camera'].replace('\x00', ' ').replace('\u0000', ' ')
            lines.append(f"Appareil : {camera}")
    else:
        lines.append("Aucune métadonnée EXIF trouvée")

    return "\n".join(lines)