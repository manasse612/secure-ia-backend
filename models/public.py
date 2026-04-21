# === Routes publiques ===
# Endpoints accessibles sans authentification
# Configuration du site, offres actives, mot de passe oublié

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta
import random

from database import get_db
from models.site_config import SiteConfig
from models.offer import Offer
from models.user import User
from models.password_reset import PasswordResetCode
from utils.security import hash_password

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
    email: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Demander un code de vérification pour réinitialiser le mot de passe.
    Envoie un code à 6 chiffres par email (simulation : retourné dans la réponse).
    """
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

    # Envoyer le code par email (SMTP) et/ou afficher en simulation
    from services.config_helper import is_simulation_mode
    from services.email_service import send_password_reset_code
    simulation = await is_simulation_mode(db)

    send_password_reset_code(email, code)

    response = {
        "message": "Un code de vérification a été envoyé à votre adresse email.",
        "expires_in_minutes": 15,
    }

    if simulation:
        response["code"] = code

    return response


@router.post("/verify-reset-code")
async def verify_reset_code(
    email: str,
    code: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Vérifier un code de réinitialisation de mot de passe.
    Retourne un token temporaire si le code est valide.
    """
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code invalide ou expiré",
        )

    if reset_code.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code expiré. Veuillez en demander un nouveau.",
        )

    # Marquer le code comme utilisé
    reset_code.is_used = True
    await db.flush()

    return {
        "message": "Code vérifié avec succès",
        "email": email,
        "verified": True,
    }


@router.post("/reset-password")
async def reset_password(
    email: str,
    code: str,
    new_password: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Réinitialiser le mot de passe après vérification du code.
    """
    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins 8 caractères",
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Aucune vérification valide trouvée. Veuillez recommencer.",
        )

    # Vérifier que le code n'a pas plus de 30 minutes
    age = (datetime.utcnow() - reset_code.created_at).total_seconds()
    if age > 1800:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La session de réinitialisation a expiré. Veuillez recommencer.",
        )

    # Mettre à jour le mot de passe
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    user.hashed_password = hash_password(new_password)
    await db.flush()

    return {"message": "Mot de passe réinitialisé avec succès. Vous pouvez vous connecter."}


# ============================================================
# Vérification d'email (après inscription)
# ============================================================

@router.post("/verify-email")
async def verify_email(
    email: str,
    code: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Vérifier l'email d'un utilisateur après inscription.
    Active le compte si le code est valide.
    """
    from models.email_verification import EmailVerificationCode
    from utils.security import create_access_token, create_refresh_token
    import uuid as uuid_mod

    result = await db.execute(
        select(EmailVerificationCode)
        .where(
            EmailVerificationCode.email == email,
            EmailVerificationCode.code == code,
            EmailVerificationCode.is_used == False,
        )
        .order_by(EmailVerificationCode.created_at.desc())
    )
    verification = result.scalar_one_or_none()

    if not verification:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code invalide. Vérifiez le code et réessayez.",
        )

    if verification.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ce code a expiré. Cliquez sur « Renvoyer le code » pour en recevoir un nouveau.",
        )

    # Marquer le code comme utilisé
    verification.is_used = True
    await db.flush()

    # Activer le compte utilisateur
    user_result = await db.execute(select(User).where(User.email == email))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Compte introuvable. Veuillez vous réinscrire.")

    user.is_verified = True

    # Générer une session et des tokens JWT pour connexion automatique
    session_token = str(uuid_mod.uuid4())
    user.active_session_token = session_token
    user.last_login = datetime.utcnow()
    await db.flush()

    access_token = create_access_token(str(user.id), user.role, session_token)
    refresh_token = create_refresh_token(str(user.id))

    from schemas.user import UserResponse
    return {
        "message": "Email vérifié avec succès ! Bienvenue sur Secure IA.",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user).model_dump(),
    }


@router.post("/resend-verification")
async def resend_verification_code(
    email: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Renvoyer un code de vérification d'email.
    """
    from models.email_verification import EmailVerificationCode
    from services.email_service import send_verification_code as send_code
    from services.config_helper import is_simulation_mode

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

    simulation = await is_simulation_mode(db)
    send_code(email, code, user.full_name or "")

    response = {
        "message": "Un nouveau code de vérification a été envoyé.",
        "expires_in_minutes": 15,
    }
    if simulation:
        response["code"] = code
    return response
