# === Routes d'analyse ===
# Gère toutes les analyses : image, texte, URL, vidéo
# Toutes les routes commencent par /api/analysis/

from uuid import UUID
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
import io

from database import get_db
from schemas.analysis import AnalysisResponse, AnalysisListResponse
from services.analysis_service import create_analysis, get_user_analyses, get_analysis_by_id
from services.api_client import validate_image_file, validate_video_file, sanitize_filename
from utils.security import get_current_user
from utils.rate_limiter import RateLimiter
from utils.rate_limiter_advanced import AdvancedRateLimiter
from utils.database_logger import log_analysis, log_security
from fastapi import Request
import logging
import traceback

logger = logging.getLogger(__name__)

# Créer le routeur avec le préfixe /api/analysis
router = APIRouter(prefix="/api/analysis", tags=["Analyses"])


@router.post("/image", response_model=AnalysisResponse, status_code=201)
async def analyze_image_route(
    request: Request,
    image_url: str = Form(default=None),
    file: UploadFile = File(default=None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyser une image pour détecter les manipulations et l'IA.
    
    Deux modes d'envoi :
    - Par URL : fournir image_url dans le formulaire
    - Par upload : envoyer le fichier dans le champ file
    
    Retourne le score d'authenticité et les détails de l'analyse.
    """
    # Protection DDoS: rate limiting strict sur les analyses
    await AdvancedRateLimiter.check_limit(request, "analysis_per_ip")
    await AdvancedRateLimiter.check_limit(request, "analysis_per_user", str(current_user.id))
    
    # Vérifier qu'au moins une source est fournie
    if not image_url and not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Veuillez fournir une URL d'image ou uploader un fichier",
        )

    # Valider l'URL si fournie
    if image_url:
        from urllib.parse import urlparse
        parsed = urlparse(image_url)
        
        # Vérifier que c'est une URL valide avec protocole http/https
        if not parsed.scheme or parsed.scheme not in ('http', 'https'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL invalide. Seuls les liens HTTP et HTTPS sont acceptés.",
            )
        
        if not parsed.netloc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL invalide. Vérifiez que le lien est complet (ex: https://exemple.com/image.jpg)",
            )
        
        # Vérifier que l'URL pointe vers une image (extension ou content-type)
        valid_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tiff', '.tif')
        path_lower = parsed.path.lower()
        has_image_extension = any(path_lower.endswith(ext) for ext in valid_extensions)
        
        # Vérifier que l'URL est accessible (optionnel - on continue même si ça échoue)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                head_response = await client.head(image_url, follow_redirects=True)
                
                if head_response.status_code != 200:
                    logger.warning(f"[Analyse Image] URL retourne {head_response.status_code}: {image_url}")
                    # On continue quand même, Hive AI essaiera de télécharger
                else:
                    # Vérifier le Content-Type
                    content_type = head_response.headers.get('content-type', '').lower()
                    if content_type and not content_type.startswith(('image/', 'application/octet-stream')):
                        logger.warning(f"[Analyse Image] Content-Type non-image: {content_type}")
                    
                    if not has_image_extension and not content_type.startswith('image/'):
                        logger.warning(f"[Analyse Image] URL sans extension ni content-type image: {image_url}")
                        # On laisse passer - certains CDN ont des URLs sans extension
                    
        except httpx.TimeoutException:
            logger.warning(f"[Analyse Image] Timeout lors de la vérification de l'URL: {image_url}")
            # On continue quand même, Hive AI essaiera de télécharger
        except httpx.RequestError as e:
            logger.warning(f"[Analyse Image] Erreur de connexion à l'URL: {image_url} - {e}")
            # On continue quand même - l'URL pourrait être accessible par Hive AI mais pas par nous (ex: URLs signées, géo-bloquées)
        except Exception as e:
            logger.warning(f"[Analyse Image] Erreur inattendue lors de la vérification: {e}")
            # On continue quand même
    
    # Lire le fichier si uploadé
    file_bytes = None
    input_filename = None
    input_data = image_url or ""
    
    logger.info(f"[Analyse Image] Mode: {'URL' if image_url else 'Upload'}, input_data: {input_data[:100] if input_data else 'None'}")

    if file:
        # Lire le fichier pour validation
        file_bytes = await file.read()

        # Vérifier le type et la taille avec validation sécurisée
        is_valid, error_message = validate_image_file(
            file.content_type or "application/octet-stream",
            len(file_bytes),
            file.filename or "unknown"
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message,
            )

        # Sanitiser le nom de fichier
        safe_filename = sanitize_filename(file.filename or "upload")
        input_filename = safe_filename
        input_data = f"upload://{safe_filename}"

        logger.info(f"[Analyse Image] Upload reçu - {safe_filename}, {len(file_bytes)} octets")

    # Lancer l'analyse
    try:
        analysis = await create_analysis(
            db=db,
            user=current_user,
            analysis_type="image",
            input_data=input_data,
            input_filename=input_filename,
            file_bytes=file_bytes,
        )
        
        # Logger le succès
        await log_analysis(
            f"Analyse image réussie - Score: {analysis.result.get('score', 'N/A')}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="info",
            details=f"Input: {input_data[:100]}..., Type: {'Upload' if file else 'URL'}"
        )
        
        return AnalysisResponse.model_validate(analysis)
        
    except HTTPException as e:
        # Logger l'erreur HTTP
        await log_analysis(
            f"Échec analyse image - {e.status_code}: {e.detail}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="warning",
            details=f"Input: {input_data[:100]}..."
        )
        raise
    except Exception as e:
        # Logger l'erreur inattendue
        await log_analysis(
            f"Erreur critique analyse image: {str(e)}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="error",
            details=traceback.format_exc()
        )
        raise


@router.post("/text", response_model=AnalysisResponse, status_code=201)
async def analyze_text_route(
    request: Request,
    text: str = Form(...),
    language: str = Form(default="fr"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyser un texte pour vérifier sa véracité (fact-checking).
    
    Paramètres :
    - text : le texte à analyser (10 à 10000 caractères)
    - language : la langue du texte (fr par défaut)
    
    Retourne le score de fiabilité et le verdict (vrai/faux/non vérifiable).
    """
    # Protection DDoS: rate limiting sur les analyses texte
    await AdvancedRateLimiter.check_limit(request, "analysis_per_ip")
    await AdvancedRateLimiter.check_limit(request, "analysis_per_user", str(current_user.id))
    
    # Vérifier la longueur du texte
    if len(text) < 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le texte doit contenir au moins 10 caractères",
        )
    if len(text) > 10000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le texte ne doit pas dépasser 10 000 caractères",
        )

    # Lancer l'analyse avec gestion d'erreur spécifique
    try:
        analysis = await create_analysis(
            db=db,
            user=current_user,
            analysis_type="text",
            input_data=text,
        )
        
        # Logger le succès
        result = analysis.result or {}
        await log_analysis(
            f"Analyse texte réussie - Score: {result.get('score', 'N/A')}, Verdict: {result.get('verdict', 'N/A')}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="info",
            details=f"Texte: {text[:100]}... (longueur: {len(text)} caractères)"
        )
        
        return AnalysisResponse.model_validate(analysis)
        
    except RuntimeError as e:
        error_msg = str(e)
        # Log dans le terminal
        logger.error(f"[Analyse Texte] ERREUR: {error_msg}")
        print(f"\n❌ [ANALYSE TEXTE] {error_msg}\n")
        
        # Logger l'erreur en base
        await log_analysis(
            f"Échec analyse texte: {error_msg[:100]}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="error",
            details=f"Erreur complète: {error_msg}\n{traceback.format_exc()}"
        )
        
        # Retourner un message clair à l'utilisateur
        if "OPENAI_API_KEY" in error_msg or "Service d'analyse indisponible" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service d'analyse de texte temporairement indisponible. Contactez l'administrateur.",
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de l'analyse: {error_msg}",
        )
    except Exception as e:
        logger.exception("[Analyse Texte] Erreur inattendue")
        print(f"\n❌ [ANALYSE TEXTE] Erreur inattendue: {str(e)}\n")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Une erreur est survenue lors de l'analyse du texte",
        )


@router.post("/url", response_model=AnalysisResponse, status_code=201)
async def analyze_url_route(
    request: Request,
    url: str = Form(...),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyser la sécurité d'une URL / site web.
    
    Paramètres :
    - url : l'URL du site à analyser
    
    Retourne le score de sécurité, le statut SSL, et la réputation.
    """
    # Protection DDoS: rate limiting sur les analyses URL
    await AdvancedRateLimiter.check_limit(request, "analysis_per_ip")
    await AdvancedRateLimiter.check_limit(request, "analysis_per_user", str(current_user.id))
    
    # Valider l'URL
    if not url or len(url) < 4:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Veuillez fournir une URL valide (ex: https://exemple.com)",
        )
    
    # Vérifier que c'est une URL HTTP/HTTPS valide
    from urllib.parse import urlparse
    parsed = urlparse(url)
    
    if not parsed.scheme or parsed.scheme not in ('http', 'https'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL invalide. Seuls les liens HTTP et HTTPS sont acceptés.",
        )
    
    if not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL invalide. Vérifiez que le lien est complet.",
        )

    # Lancer l'analyse
    try:
        analysis = await create_analysis(
            db=db,
            user=current_user,
            analysis_type="url",
            input_data=url,
        )
        
        # Logger le succès
        result = analysis.result or {}
        await log_analysis(
            f"Analyse URL réussie - Score: {result.get('score', 'N/A')}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="info",
            details=f"URL: {url[:100]}..."
        )
        
        return AnalysisResponse.model_validate(analysis)
        
    except Exception as e:
        # Logger l'erreur
        await log_analysis(
            f"Échec analyse URL: {str(e)[:100]}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="error",
            details=f"URL: {url}\n{traceback.format_exc()}"
        )
        raise


@router.post("/video", response_model=AnalysisResponse, status_code=201)
async def analyze_video_route(
    request: Request,
    video_url: str = Form(default=None),
    file: UploadFile = File(default=None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyser une vidéo pour détecter les deepfakes et manipulations.
    
    Deux modes d'envoi :
    - Par URL : fournir video_url dans le formulaire
    - Par upload : envoyer le fichier vidéo dans le champ file
    
    Retourne le score d'authenticité et les détails de l'analyse.
    """
    # Protection DDoS: rate limiting strict sur les vidéos (ressources intensives)
    await AdvancedRateLimiter.check_limit(request, "analysis_per_ip")
    await AdvancedRateLimiter.check_limit(request, "analysis_per_user", str(current_user.id))
    
    if not video_url and not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Veuillez fournir une URL vidéo ou uploader un fichier",
        )
    
    # Valider l'URL si fournie
    if video_url:
        from urllib.parse import urlparse
        parsed = urlparse(video_url)
        
        if not parsed.scheme or parsed.scheme not in ('http', 'https'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL invalide. Seuls les liens HTTP et HTTPS sont acceptés.",
            )
        
        if not parsed.netloc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="URL invalide. Vérifiez que le lien est complet.",
            )
        
        # Vérifier l'extension vidéo
        valid_video_ext = ('.mp4', '.webm', '.m4v', '.mov', '.avi', '.mkv')
        path_lower = parsed.path.lower()
        if not any(path_lower.endswith(ext) for ext in valid_video_ext):
            logger.warning(f"[Analyse Vidéo] URL sans extension vidéo: {video_url}")

    file_bytes = None
    input_filename = None
    input_data = video_url or ""

    if file:
        # Lire le fichier pour validation
        file_bytes = await file.read()

        # Vérifier le type et la taille avec validation sécurisée
        is_valid, error_message = validate_video_file(
            file.content_type or "application/octet-stream",
            len(file_bytes),
            file.filename or "unknown"
        )

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_message,
            )

        # Sanitiser le nom de fichier
        safe_filename = sanitize_filename(file.filename or "upload")
        input_filename = safe_filename
        input_data = f"upload://{safe_filename}"

        logger.info(f"[Analyse Vidéo] Upload reçu - {safe_filename}, {len(file_bytes)} octets")

    try:
        analysis = await create_analysis(
            db=db,
            user=current_user,
            analysis_type="video",
            input_data=input_data,
            input_filename=input_filename,
            file_bytes=file_bytes,
        )
        
        # Logger le succès
        result = analysis.result or {}
        await log_analysis(
            f"Analyse vidéo réussie - Score: {result.get('score', 'N/A')}, Verdict: {result.get('verdict', 'N/A')}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="info",
            details=f"Input: {input_data[:100]}..., Type: {'Upload' if file else 'URL'}"
        )
        
        return AnalysisResponse.model_validate(analysis)
        
    except Exception as e:
        # Logger l'erreur
        await log_analysis(
            f"Échec analyse vidéo: {str(e)[:100]}",
            ip=request.client.host,
            user_id=str(current_user.id),
            level="error",
            details=f"Input: {input_data[:100]}...\n{traceback.format_exc()}"
        )
        raise


@router.get("/quota")
async def get_quota(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),  # AJOUT : db est maintenant requis
):
    """
    Récupérer le quota d'analyses restant pour l'utilisateur connecté.
    Retourne le plan, la limite, le nombre utilisé et le nombre restant.
    """
    # CORRECTION : Passage de la DB à RateLimiter
    return await RateLimiter.get_remaining_analyses(current_user, db)


@router.get("/history", response_model=AnalysisListResponse)
async def get_history(
    page: int = 1,
    per_page: int = 10,
    analysis_type: str = None,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Récupérer l'historique des analyses de l'utilisateur.
    
    Paramètres :
    - page : numéro de page (défaut 1)
    - per_page : nombre de résultats par page (défaut 10)
    - analysis_type : filtrer par type (image, text, url, video)
    
    Note : les utilisateurs gratuits ne voient que les 10 dernières analyses.
    """
    # Limiter à 10 pour les utilisateurs gratuits
    if current_user.role == 'free':
        per_page = min(per_page, 10)

    result = await get_user_analyses(
        db=db,
        user_id=current_user.id,
        page=page,
        per_page=per_page,
        analysis_type=analysis_type,
    )

    return AnalysisListResponse(
        analyses=[AnalysisResponse.model_validate(a) for a in result["analyses"]],
        total=result["total"],
        page=result["page"],
        per_page=result["per_page"],
    )


@router.delete("/history")
async def clear_history(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Supprimer tout l'historique des analyses de l'utilisateur connecté.
    """
    from sqlalchemy import delete as sa_delete
    from models.analysis import Analysis

    result = await db.execute(
        sa_delete(Analysis).where(Analysis.user_id == current_user.id)
    )
    deleted_count = result.rowcount
    await db.flush()

    return {"message": f"{deleted_count} analyse(s) supprimée(s)", "deleted": deleted_count}


@router.get("/{analysis_id}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_id: UUID,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Récupérer les détails d'une analyse par son ID.
    L'utilisateur ne peut voir que ses propres analyses.
    """
    analysis = await get_analysis_by_id(db, analysis_id, current_user.id)
    return AnalysisResponse.model_validate(analysis)


@router.get("/{analysis_id}/pdf")
async def export_analysis_pdf(
    analysis_id: UUID,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Exporter une analyse au format PDF.
    Génère un rapport complet téléchargeable.
    L'utilisateur ne peut exporter que ses propres analyses.
    """
    # Récupérer l'analyse
    analysis = await get_analysis_by_id(db, analysis_id, current_user.id)

    # Préparer les données pour le PDF
    analysis_dict = {
        "analysis_type": analysis.analysis_type.value if hasattr(analysis.analysis_type, 'value') else analysis.analysis_type,
        "input_data": analysis.input_data,
        "score": analysis.score,
        "verdict": analysis.verdict,
        "summary": analysis.summary,
        "result": analysis.result,
        "processing_time_ms": analysis.processing_time_ms,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
    }

    # Générer le PDF
    from services.pdf_service import generate_analysis_pdf
    pdf_bytes = generate_analysis_pdf(analysis_dict)

    # Retourner le PDF en téléchargement
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="secure-ia-rapport-{analysis_id}.pdf"'
        },
    )