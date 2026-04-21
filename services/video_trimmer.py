# === Utilitaire de découpe vidéo ===
# Coupe une vidéo à une durée maximale avant envoi à l'API Hive AI
# Utilise moviepy (ffmpeg) pour le transcodage

import tempfile
import os
from typing import Optional


def trim_video_bytes(video_bytes: bytes, max_duration: float = 55.0, filename: str = "video.mp4") -> tuple[bytes, str]:
    """
    Découper une vidéo en mémoire à max_duration secondes.
    
    Retourne (trimmed_bytes, info_message).
    - Si la vidéo est déjà <= max_duration, retourne les bytes originaux.
    - Sinon, coupe et retourne les bytes du fichier découpé.
    
    max_duration est fixé à 55s (marge de sécurité pour la limite Hive AI de 60s).
    L'utilisateur peut uploader des vidéos de 2 min, mais seules les 55 premières
    secondes sont analysées par Hive AI.
    """
    from moviepy import VideoFileClip

    # Écrire les bytes dans un fichier temporaire
    suffix = os.path.splitext(filename)[1] or ".mp4"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp_in:
        tmp_in.write(video_bytes)
        tmp_in_path = tmp_in.name

    try:
        clip = VideoFileClip(tmp_in_path)
        duration = clip.duration

        if duration is None or duration <= max_duration:
            # Pas besoin de couper
            clip.close()
            return video_bytes, f"Vidéo complète ({duration:.1f}s)" if duration else "Vidéo complète"

        # Couper aux premières max_duration secondes
        trimmed = clip.subclipped(0, max_duration)

        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp_out:
            tmp_out_path = tmp_out.name

        trimmed.write_videofile(
            tmp_out_path,
            codec="libx264",
            audio_codec="aac",
            logger=None,  # Pas de logs verbose
        )

        trimmed.close()
        clip.close()

        with open(tmp_out_path, "rb") as f:
            trimmed_bytes = f.read()

        os.unlink(tmp_out_path)

        return trimmed_bytes, f"Vidéo découpée : {duration:.0f}s -> {max_duration:.0f}s"

    finally:
        # Nettoyer le fichier temporaire d'entrée
        try:
            os.unlink(tmp_in_path)
        except OSError:
            pass
