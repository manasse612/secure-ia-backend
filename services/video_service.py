# === Service d'analyse vidéo ===
# Détection de deepfakes et de contenus vidéo manipulés
# Utilise l'API Hive AI pour la détection

import time
from typing import Optional


async def analyze_video(
    video_url: str = None,
    video_bytes: bytes = None,
    filename: str = None,
) -> dict:
    """
    Analyser une vidéo pour détecter les deepfakes et manipulations.
    Appelle l'API Hive AI pour la détection.
    """
    start_time = time.time()

    # Vérifier qu'on a des données à analyser
    if not video_url and not video_bytes:
        return {
            "score": 0,
            "verdict": "erreur",
            "summary": "Aucune vidéo fournie pour l'analyse.",
            "processing_time_ms": 0,
        }

    return await _real_video_analysis(video_url, video_bytes, start_time, filename)


def _get_recommendations(verdict: str, probability: float) -> list:
    """Générer des recommandations basées sur le verdict."""
    recs = []
    if verdict == "authentique":
        recs.append("La vidéo semble authentique. Aucune manipulation majeure détectée.")
        recs.append("Vérifiez toujours la source originale de la vidéo.")
    elif verdict == "suspect":
        recs.append("Des éléments suspects ont été détectés. Prudence recommandée.")
        recs.append("Comparez avec d'autres sources pour confirmer l'authenticité.")
        recs.append("Les incohérences temporelles méritent une attention particulière.")
    else:
        recs.append("Forte probabilité de deepfake. Ne partagez pas cette vidéo comme authentique.")
        recs.append("Recherchez la source originale et vérifiez le contexte.")
        recs.append("Signalez le contenu si nécessaire auprès de la plateforme d'origine.")
    return recs


async def _real_video_analysis(
    video_url: str = None,
    video_bytes: bytes = None,
    start_time: float = None,
    filename: str = None,
) -> dict:
    """
    Analyse vidéo réelle via l'API Hive AI.
    Détecte les deepfakes visuels, le contenu généré par IA et l'audio synthétique.
    """
    from config import settings
    from services.hive_service import hive_detect

    if start_time is None:
        start_time = time.time()

    # Vérifier que la clé API Hive est configurée
    if not settings.hive_api_key:
        raise RuntimeError(
            "HIVE_API_KEY non configurée. "
            "Veuillez configurer votre clé API Hive dans le fichier .env"
        )

    # Découper la vidéo si elle est trop longue (limite Hive AI : 60s)
    # L'utilisateur peut uploader jusqu'à 2 min, mais seules les 55 premières
    # secondes sont envoyées à Hive AI (marge de sécurité de 5s)
    trim_info = None
    if video_bytes:
        original_size = len(video_bytes)
        try:
            import asyncio
            from services.video_trimmer import trim_video_bytes
            video_bytes, trim_info = await asyncio.to_thread(
                trim_video_bytes,
                video_bytes,
                55.0,
                filename or "video.mp4",
            )
            print(f"[VIDEO] {trim_info} | Taille : {original_size/(1024*1024):.1f} Mo -> {len(video_bytes)/(1024*1024):.1f} Mo")
        except Exception as e:
            # Si le trimming échoue, on envoie la vidéo telle quelle
            trim_info = f"Découpe échouée : {str(e)}"
            print(f"[VIDEO] ERREUR trimming : {e}")

    # Appeler l'API Hive AI
    hive_result = await hive_detect(
        media_url=video_url,
        media_bytes=video_bytes,
        filename=filename or "video.mp4",
    )

    if "error" in hive_result:
        raise RuntimeError(f"Erreur Hive AI : {hive_result['error']}")

    # Extraire les scores principaux
    ai_prob = hive_result.get("ai_generated_probability", 0)
    deepfake_prob = hive_result.get("deepfake_probability", 0)
    audio_prob = hive_result.get("ai_audio_probability", 0)
    generators = hive_result.get("generator_attribution", {})
    frames = hive_result.get("frames", [])
    total_frames = hive_result.get("total_frames", 0)

    # Score d'authenticité (inverse du max entre ai_generated et deepfake)
    max_threat = max(ai_prob, deepfake_prob)
    authenticity_score = round((1 - max_threat) * 100)

    # Déterminer le verdict avec seuils standardisés (70/40 comme les autres services)
    # max_threat > 0.6 → score < 40 (deepfake)
    # max_threat > 0.3 → score < 70 (suspect)
    if max_threat > 0.6:
        verdict = "deepfake"
        verdict_label = "Deepfake probable détecté (Hive AI)"
    elif max_threat > 0.3:
        verdict = "suspect"
        verdict_label = "Vidéo suspecte, manipulation possible (Hive AI)"
    else:
        verdict = "authentique"
        verdict_label = "Vidéo probablement authentique (Hive AI)"

    # Compter les frames suspectes (ai_generated >= 0.5)
    suspicious_frames = 0
    for f in frames:
        scores = f.get("scores", {})
        if scores.get("ai_generated", 0) >= 0.5 or scores.get("deepfake", 0) >= 0.5:
            suspicious_frames += 1

    # Analyse audio
    audio_analysis = {
        "has_audio": audio_prob > 0,
        "voice_synthetic_probability": round(audio_prob, 4),
        "ai_generated_audio": round(audio_prob, 4),
    }

    # Analyse faciale (basée sur deepfake score)
    face_analysis = {
        "face_swap_probability": round(deepfake_prob, 4),
        "deepfake_confidence": round(deepfake_prob, 4),
    }

    # Métadonnées vidéo
    video_metadata = {
        "total_frames_analyzed": total_frames,
        "suspicious_frames": suspicious_frames,
    }

    # Générateur IA le plus probable
    model_detected = None
    if generators:
        top_gen = max(generators.items(), key=lambda x: x[1])
        if top_gen[0] != "none" and top_gen[1] > 0.1:
            model_detected = top_gen[0]

    processing_time = int((time.time() - start_time) * 1000)

    # Format standardisé compatible avec le frontend
    return {
        "score": authenticity_score,
        "verdict": verdict,
        "summary": verdict_label,
        "processing_time_ms": processing_time,
        "provider": "hive_ai",
        # Analyses détaillées
        "ai_generated_probability": round(ai_prob, 4),
        "deepfake_probability": round(deepfake_prob, 4),
        "manipulation_score": round(max_threat * 100, 2),
        "audio_analysis": audio_analysis,
        "face_analysis": face_analysis,
        "temporal_analysis": {
            "frame_consistency_score": round(1 - (suspicious_frames / max(total_frames, 1)), 4),
            "compression_artifacts": "none" if suspicious_frames == 0 else "detected",
            "temporal_flickering_detected": suspicious_frames > 0,
            "resolution_consistency": "stable",
        },
        "video_metadata": {
            **video_metadata,
            "duration_seconds": 55 if trim_info else 60,
            "resolution": "inconnue",
            "fps": 30,
            "codec": "auto",
        },
        "models_used": [{"name": "Hive AI", "version": "v3", "confidence": round(max_threat, 4)}],
        "recommendations": _get_recommendations(verdict, max_threat),
    }
