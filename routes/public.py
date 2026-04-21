# === Routes publiques ===
# Endpoints accessibles sans authentification
# Configuration du site, offres actives, mot de passe oublié
from fastapi import Request, APIRouter, Depends, HTTPException, status, Body, Form
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from datetime import datetime, timedelta
import random
import logging
import uuid

from database import get_db
from models.site_config import SiteConfig
from models.offer import Offer
from models.user import User
from models.password_reset import PasswordResetCode
from models.email_verification import EmailVerificationCode
from utils.security import hash_password, create_access_token, create_refresh_token

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/public", tags=["Public"])


# ============================================================
# Configuration publique (prix, quotas)
# ============================================================

@router.get("/config")
async def get_public_config(db: AsyncSession = Depends(get_db)):
    """
    Récupérer la configuration publique du site.
    Utilisé par le frontend pour afficher les prix et quotas dynamiquement.
    """
    from services.config_helper import get_plan_pricing, get_plan_quotas

    pricing = await get_plan_pricing(db)
    quotas = await get_plan_quotas(db)

    return {
        "pricing": pricing,
        "quotas": quotas,
        "plans": [
            {
                "id": "free",
                "name": "Gratuit",
                "price": pricing["free"],
                "quota": quotas.get("free", 10),
                "features": [
                    "Analyse d'images",
                    "Analyse de texte",
                    "Analyse URL basique",
                    "Historique (10 dernières)",
                    "Export PDF simple",
                ],
            },
            {
                "id": "pro",
                "name": "Pro",
                "price": pricing["pro"],
                "quota": quotas.get("pro", 500),
                "popular": True,
                "features": [
                    "Analyse d'images avancée",
                    "Fact-checking avancé",
                    "Scan site web complet",
                    "Analyse vidéo deepfake",
                    "Historique complet",
                    "Rapports PDF sans marque",
                    "Support prioritaire",
                ],
            },
            {
                "id": "business",
                "name": "Business",
                "price": pricing["business"],
                "quota": quotas.get("business", 5000),
                "features": [
                    "Tout le plan Pro",
                    "API + clés d'accès",
                    "Équipe (5 membres)",
                    "Exports CSV",
                    "Support dédié",
                    "Documentation API",
                    "Logs d'appels API",
                ],
            },
        ],
    }


# ============================================================
# Offres actives (page d'accueil)
# ============================================================

@router.get("/offers")
async def get_active_offers(db: AsyncSession = Depends(get_db)):
    """
    Récupérer les offres actuellement actives.
    Affichées sur la page d'accueil.
    """
    now = datetime.utcnow()
    query = (
        select(Offer)
        .where(Offer.is_active == True)
        .where(
            (Offer.start_date.is_(None)) | (Offer.start_date <= now)
        )
        .where(
            (Offer.end_date.is_(None)) | (Offer.end_date >= now)
        )
        .order_by(Offer.created_at.desc())
    )

    result = await db.execute(query)
    offers = result.scalars().all()

    return {
        "offers": [
            {
                "id": str(o.id),
                "title": o.title,
                "description": o.description,
                "badge_text": o.badge_text,
                "badge_color": o.badge_color,
                "image_url": o.image_url,
                "cta_text": o.cta_text,
                "cta_link": o.cta_link,
                "start_date": o.start_date.isoformat() if o.start_date else None,
                "end_date": o.end_date.isoformat() if o.end_date else None,
            }
            for o in offers
        ]
    }


# ============================================================
# Mot de passe oublié
# ============================================================

@router.post("/forgot-password")
async def forgot_password(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Demander un code de vérification pour réinitialiser le mot de passe.
    Accepte l'email en body JSON, form-data, ou query params.
    Envoie un code à 6 chiffres par email.
    """
    try:
        # Essayer de récupérer l'email de différentes façons
        email = None
        
        # 1. Essayer query params d'abord (car c'est ce que le frontend envoie)
        email = request.query_params.get('email')
        
        # 2. Si pas en query, essayer body JSON
        if not email:
            try:
                body = await request.json()
                email = body.get('email')
            except Exception as e:
                logger.debug(f"[Forgot Password] JSON parsing failed: {type(e).__name__}")
        
        # 3. Si pas en JSON, essayer form-data
        if not email:
            try:
                form = await request.form()
                email = form.get('email')
            except Exception as e:
                logger.debug(f"[Forgot Password] Form parsing failed: {type(e).__name__}")
        
        if not email:
            return JSONResponse(
                status_code=400,
                content={"message": "L'email est requis"}
            )
        
        # Vérifier que l'utilisateur existe
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            # Ne pas révéler si l'email existe ou non (sécurité)
            return {"message": "Si cet email existe, un code de vérification a été envoyé."}

        # Générer un code à 6 chiffres
        code = str(random.randint(100000, 999999))

        # Sauvegarder le code en base
        reset_code = PasswordResetCode(
            email=email,
            code=code,
            expires_at=datetime.utcnow() + timedelta(minutes=15),
        )
        db.add(reset_code)
        await db.flush()

        # Envoyer le code par email (SMTP)
        from services.email_service import send_password_reset_code
        send_password_reset_code(email, code)

        return {
            "message": "Un code de vérification a été envoyé à votre adresse email.",
            "expires_in_minutes": 15,
        }
        
    except Exception as e:
        # Ne pas exposer les détails d'erreur internes (SQL, etc.)
        logger.error(f"Error in forgot_password: {type(e).__name__}")
        return JSONResponse(
            status_code=500,
            content={"message": "Erreur lors de l'envoi du code. Veuillez réessayer plus tard."}
        )


@router.post("/verify-reset-code")
async def verify_reset_code(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Vérifier un code de réinitialisation de mot de passe.
    Accepte email et code en body JSON ou query params.
    """
    try:
        # Essayer de récupérer depuis query params d'abord
        email = request.query_params.get('email')
        code = request.query_params.get('code')
        
        # Si pas en query, essayer body JSON
        if not email or not code:
            try:
                body = await request.json()
                email = body.get('email')
                code = body.get('code')
            except Exception as e:
                logger.debug(f"[Verify Reset Code] JSON parsing failed: {type(e).__name__}")
        
        # Si pas en JSON, essayer form-data
        if not email or not code:
            try:
                form = await request.form()
                email = form.get('email')
                code = form.get('code')
            except Exception as e:
                logger.debug(f"[Verify Reset Code] Form parsing failed: {type(e).__name__}")
        
        if not email or not code:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Email et code requis"}
            )
        
        result = await db.execute(
            select(PasswordResetCode)
            .where(
                PasswordResetCode.email == email,
                PasswordResetCode.code == code,
                PasswordResetCode.is_used == False,
            )
            .order_by(PasswordResetCode.created_at.desc())
        )
        reset_code = result.scalar_one_or_none()

        if not reset_code:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Code invalide ou expiré"}
            )

        if reset_code.is_expired:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Code expiré. Veuillez en demander un nouveau."}
            )

        # Marquer le code comme utilisé
        reset_code.is_used = True
        await db.flush()

        return {
            "success": True,
            "message": "Code vérifié avec succès",
            "email": email,
            "verified": True,
        }
        
    except Exception as e:
        # Ne pas exposer les détails d'erreur internes
        logger.error(f"Error in verify_reset_code: {type(e).__name__}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Erreur serveur. Veuillez réessayer."}
        )


@router.post("/reset-password")
async def reset_password(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Réinitialiser le mot de passe après vérification du code.
    Accepte email, code et new_password en body JSON ou query params.
    """
    try:
        # Essayer de récupérer depuis query params d'abord
        email = request.query_params.get('email')
        code = request.query_params.get('code')
        new_password = request.query_params.get('new_password')
        
        # Si pas en query, essayer body JSON
        if not email or not code or not new_password:
            try:
                body = await request.json()
                email = body.get('email')
                code = body.get('code')
                new_password = body.get('new_password')
            except Exception as e:
                logger.debug(f"[Reset Password] JSON parsing failed: {type(e).__name__}")
        
        # Si pas en JSON, essayer form-data
        if not email or not code or not new_password:
            try:
                form = await request.form()
                email = form.get('email')
                code = form.get('code')
                new_password = form.get('new_password')
            except Exception as e:
                logger.debug(f"[Reset Password] Form parsing failed: {type(e).__name__}")
        
        if not email or not code or not new_password:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Email, code et nouveau mot de passe requis"}
            )

        if len(new_password) < 8:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Le mot de passe doit contenir au moins 8 caractères"}
            )

        # Vérifier qu'un code a été vérifié récemment pour cet email
        result = await db.execute(
            select(PasswordResetCode)
            .where(
                PasswordResetCode.email == email,
                PasswordResetCode.code == code,
                PasswordResetCode.is_used == True,
            )
            .order_by(PasswordResetCode.created_at.desc())
        )
        reset_code = result.scalar_one_or_none()

        if not reset_code:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Aucune vérification valide trouvée. Veuillez recommencer."}
            )

        # Vérifier que le code n'a pas plus de 30 minutes
        age = (datetime.utcnow() - reset_code.created_at).total_seconds()
        if age > 1800:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "La session de réinitialisation a expiré. Veuillez recommencer."}
            )

        # Mettre à jour le mot de passe
        user_result = await db.execute(select(User).where(User.email == email))
        user = user_result.scalar_one_or_none()

        if not user:
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "Utilisateur non trouvé"}
            )

        user.hashed_password = hash_password(new_password)
        await db.flush()

        return {"success": True, "message": "Mot de passe réinitialisé avec succès. Vous pouvez vous connecter."}
        
    except Exception as e:
        # Ne pas exposer les détails d'erreur internes
        logger.error(f"Error in reset_password: {type(e).__name__}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Erreur lors de la réinitialisation. Veuillez réessayer."}
        )


# ============================================================
# Vérification d'email (après inscription)
# ============================================================

@router.post("/verify-email")
async def verify_email(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Vérifie l'email avec le code reçu (accepte body ou query params)"""
    try:
        # Essayer de récupérer depuis query params d'abord
        email = request.query_params.get('email')
        code = request.query_params.get('code')
        
        # Si pas en query, essayer body JSON
        if not email or not code:
            try:
                body = await request.json()
                email = body.get('email')
                code = body.get('code')
            except Exception as e:
                logger.debug(f"[Verify Email] JSON parsing failed: {type(e).__name__}")
        
        if not email or not code:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Email et code requis"}
            )
        
        # Chercher l'utilisateur
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        
        if not user:
            return JSONResponse(
                status_code=404,
                content={"success": False, "message": "Utilisateur non trouvé"}
            )
        
        if user.is_verified:
            # Si déjà vérifié, on génère quand même des tokens pour la connexion
            session_token = str(uuid.uuid4())
            user.active_session_token = session_token
            user.last_login = datetime.utcnow()
            await db.flush()
            
            access_token = create_access_token(str(user.id), user.role, session_token)
            refresh_token = create_refresh_token(str(user.id))
            
            return JSONResponse(
                content={
                    "success": True,
                    "message": "Email déjà vérifié. Connexion automatique.",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "user": {
                        "id": str(user.id),
                        "email": user.email,
                        "full_name": user.full_name,
                        "role": user.role,
                        "is_verified": user.is_verified
                    }
                }
            )
        
        # Chercher le code de vérification par EMAIL
        result = await db.execute(
            select(EmailVerificationCode)
            .where(EmailVerificationCode.email == email)
            .where(EmailVerificationCode.code == code)
            .where(EmailVerificationCode.is_used == False)
            .order_by(EmailVerificationCode.created_at.desc())
        )
        verification = result.scalar_one_or_none()
        
        if not verification:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Code invalide"}
            )
        
        if verification.is_expired:
            return JSONResponse(
                status_code=400,
                content={"success": False, "message": "Code expiré"}
            )
        
        # Valider l'utilisateur
        user.is_verified = True
        verification.is_used = True
        
        # Générer un session_token pour la nouvelle session
        session_token = str(uuid.uuid4())
        user.active_session_token = session_token
        user.last_login = datetime.utcnow()
        
        await db.flush()
        
        # Générer les tokens avec la signature correcte : (user_id, role, session_token)
        access_token = create_access_token(str(user.id), user.role, session_token)
        refresh_token = create_refresh_token(str(user.id))
        
        return JSONResponse(
            content={
                "success": True,
                "message": "Email vérifié avec succès. Vous êtes maintenant connecté.",
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
                "user": {
                    "id": str(user.id),
                    "email": user.email,
                    "full_name": user.full_name,
                    "role": user.role,
                    "is_verified": user.is_verified
                }
            }
        )
        
    except Exception as e:
        # Ne pas exposer les détails d'erreur internes
        logger.error(f"Error verifying email: {type(e).__name__}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "Erreur lors de la vérification. Veuillez réessayer."}
        )


@router.post("/resend-verification")
async def resend_verification_code(
    email: str = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Renvoyer un code de vérification d'email.
    """
    from services.email_service import send_verification_code as send_code

    # Vérifier que l'utilisateur existe et n'est pas déjà vérifié
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()

    if not user:
        return {"message": "Si cet email est enregistré, un nouveau code a été envoyé."}

    if user.is_verified:
        return {"message": "Votre email est déjà vérifié. Vous pouvez vous connecter."}

    # Générer un nouveau code
    code = str(random.randint(100000, 999999))
    verification = EmailVerificationCode(
        email=email,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=15),
    )
    db.add(verification)
    await db.flush()

    send_code(email, code, user.full_name or "")

    return {
        "message": "Un nouveau code de vérification a été envoyé.",
        "expires_in_minutes": 15,
    }