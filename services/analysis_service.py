# === Service principal d'analyse ===
# Orchestre les différents types d'analyses (image, texte, URL, vidéo)
# Gère le compteur d'analyses et l'enregistrement en base de données

from datetime import datetime
from uuid import UUID
import hashlib
import base64
import re

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from fastapi import HTTPException, status

from models.analysis import Analysis
from models.user import User
from services.image_service import analyze_image
from services.text_service import analyze_text
from services.url_service import analyze_url
from services.video_service import analyze_video
from utils.rate_limiter import RateLimiter


def parse_data_url(data_url: str) -> tuple:
    """
    Parser une data URL base64 (ex: data:image/webp;base64,UklGR...)
    Retourne (mime_type, bytes) ou (None, None) si invalide
    """
    pattern = r'^data:([^;]+);base64,(.+)$'
    match = re.match(pattern, data_url)
    if match:
        mime_type = match.group(1)
        base64_data = match.group(2)
        try:
            data_bytes = base64.b64decode(base64_data)
            return mime_type, data_bytes
        except Exception:
            return None, None
    return None, None


def calculate_file_hash(data: bytes) -> str:
    """
    Calculer le hash SHA-256 des données pour preuve d'intégrité.
    Ce hash est stocké avec l'analyse pour prouver que le fichier n'a pas été modifié.
    """
    if not data:
        return None
    return hashlib.sha256(data).hexdigest()


async def create_analysis(
    db: AsyncSession,
    user: User,
    analysis_type: str,
    input_data: str,
    input_filename: str = None,
    file_bytes: bytes = None,
) -> Analysis:
    """
    Créer et exécuter une nouvelle analyse.
    
    Étapes :
    1. Vérifier la limite d'analyses de l'utilisateur (avec DB)
    2. Créer l'enregistrement en base (statut : en cours)
    3. Lancer l'analyse appropriée selon le type
    4. Sauvegarder les résultats
    5. Incrémenter le compteur d'analyses
    """
    # --- Étape 1 : Vérifier la limite d'analyses (AVEC DB) ---
    await RateLimiter.check_analysis_limit(user, db)

    # --- Étape 2 : Créer l'enregistrement en base ---
    analysis = Analysis(
        user_id=user.id,
        analysis_type=analysis_type,
        status="processing",
        input_data=input_data,
        input_filename=input_filename,
    )
    db.add(analysis)
    await db.flush()

    # --- Étape 3 : Préparer les données selon le type ---
    image_url = None
    image_bytes = file_bytes
    video_url = None
    video_bytes = file_bytes
    file_hash = None  # Initialiser pour éviter l'erreur
    
    # --- Étape 4 : Lancer l'analyse selon le type ---
    try:
        if analysis_type == "image":
            # Déterminer le type d'entrée : URL http/https, data URL base64, ou upload
            if input_data.startswith(("http://", "https://")):
                # URL normale
                image_url = input_data
            elif input_data.startswith("data:image/"):
                # Data URL base64 (collée depuis le presse-papier)
                mime_type, data_bytes = parse_data_url(input_data)
                if data_bytes:
                    image_bytes = data_bytes
                    input_filename = f"pasted_image.{mime_type.split('/')[-1] if mime_type else 'png'}"
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Image base64 invalide. Veuillez uploader un fichier ou fournir une URL HTTP/HTTPS.",
                    )
            
            # Calculer le hash si on a des bytes (upload ou base64)
            if image_bytes:
                file_hash = calculate_file_hash(image_bytes)
            
            results = await analyze_image(
                image_url=image_url,
                image_bytes=image_bytes,
                filename=input_filename or "image.jpg",
            )
        elif analysis_type == "text":
            results = await analyze_text(text=input_data)
        elif analysis_type == "url":
            results = await analyze_url(url=input_data)
        elif analysis_type == "video":
            # Déterminer si c'est une URL ou un upload
            if input_data.startswith(("http://", "https://")):
                video_url = input_data
            else:
                video_bytes = file_bytes
            
            # Calculer le hash si on a des bytes
            if video_bytes:
                file_hash = calculate_file_hash(video_bytes)
            
            results = await analyze_video(
                video_url=video_url,
                video_bytes=video_bytes,
                filename=input_filename,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Type d'analyse non supporté : {analysis_type}",
            )

        # --- Étape 5 : Sauvegarder les résultats ---
        analysis.status = "completed"
        analysis.score = results.get("score", 0)
        analysis.verdict = results.get("verdict", "non_verifiable")
        
        # Ajouter le hash au résultat pour preuve d'intégrité
        if file_hash:
            results["file_integrity"] = {
                "hash_sha256": file_hash,
                "hash_algorithm": "SHA-256",
                "verified_at": datetime.utcnow().isoformat(),
            }
        
        analysis.result = results
        analysis.summary = results.get("summary", "")
        analysis.processing_time_ms = results.get("processing_time_ms", 0)
        analysis.completed_at = datetime.utcnow()

    except HTTPException:
        raise
    except Exception as e:
        # En cas d'erreur, marquer l'analyse comme échouée
        analysis.status = "failed"
        analysis.summary = f"Erreur lors de l'analyse : {str(e)}"
        await db.flush()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'analyse : {str(e)}",
        )

    # --- Étape 5 : Incrémenter le compteur ---
    current_count = int(user.monthly_analysis_count or "0")
    user.monthly_analysis_count = str(current_count + 1)

    await db.flush()
    return analysis


async def get_user_analyses(
    db: AsyncSession,
    user_id: UUID,
    page: int = 1,
    per_page: int = 10,
    analysis_type: str = None,
) -> dict:
    """
    Récupérer l'historique des analyses d'un utilisateur.
    Avec pagination et filtrage par type.
    """
    # Construire la requête de base
    query = select(Analysis).where(Analysis.user_id == user_id)

    # Filtrer par type si spécifié
    if analysis_type:
        query = query.where(Analysis.analysis_type == analysis_type)

    # Compter le total
    count_query = select(func.count()).select_from(
        query.subquery()
    )
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Appliquer la pagination et le tri
    query = query.order_by(Analysis.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    analyses = result.scalars().all()

    return {
        "analyses": analyses,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


async def get_analysis_by_id(db: AsyncSession, analysis_id: UUID, user_id: UUID) -> Analysis:
    """
    Récupérer une analyse par son ID.
    Vérifie que l'analyse appartient bien à l'utilisateur.
    """
    result = await db.execute(
        select(Analysis).where(
            Analysis.id == analysis_id,
            Analysis.user_id == user_id,
        )
    )
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analyse non trouvée",
        )

    return analysis