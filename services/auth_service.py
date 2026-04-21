# === Service d'authentification ===
# Gère l'inscription, la connexion, et l'authentification OAuth Google
# Toute la logique métier liée aux utilisateurs est ici

from datetime import datetime
from typing import Optional
from uuid import UUID
import uuid as uuid_mod
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status

from models.user import User
from models.subscription import Subscription
from schemas.user import UserCreate, UserLogin, UserResponse, TokenResponse
from utils.security import hash_password, verify_password, create_access_token, create_refresh_token

logger = logging.getLogger(__name__)


async def register_user(db: AsyncSession, user_data: UserCreate) -> dict:
    """
    Inscrire un nouvel utilisateur.
    Étapes :
    1. Vérifier que l'email n'existe pas déjà
    2. Hacher le mot de passe
    3. Créer l'utilisateur en base (non vérifié)
    4. Créer un abonnement gratuit par défaut (avec quota de la config)
    5. Envoyer un code de vérification par email
    """
    import random
    from datetime import timedelta
    from models.email_verification import EmailVerificationCode
    from services.email_service import send_verification_code
    from services.config_helper import get_config_value

    # Étape 1 : Vérifier l'unicité de l'email
    existing = await db.execute(select(User).where(User.email == user_data.email))
    existing_user = existing.scalar_one_or_none()

    if existing_user:
        if not existing_user.is_verified:
            # Compte existant non vérifié : renvoyer un code
            code = str(random.randint(100000, 999999))
            verification = EmailVerificationCode(
                email=user_data.email,
                code=code,
                expires_at=datetime.utcnow() + timedelta(minutes=15),
            )
            db.add(verification)
            await db.flush()

            send_verification_code(user_data.email, code, existing_user.full_name or "")

            return {
                "message": "Un code de vérification a été envoyé à votre adresse email.",
                "email": user_data.email,
                "requires_verification": True,
            }
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte existe déjà avec cet email. Connectez-vous ou utilisez \"Mot de passe oublié\".",
        )

    # Étape 2 : Créer l'utilisateur (non vérifié)
    new_user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hash_password(user_data.password),
        role="free",
        auth_provider="local",
        language=user_data.language or "fr",
        is_active=True,
        is_verified=False,
        monthly_analysis_count="0",
    )
    db.add(new_user)
    await db.flush()

    # Étape 3 : Créer l'abonnement gratuit (AVEC LE QUOTA DE LA CONFIG)
    quota_free = await get_config_value("quota_free", db)
    subscription = Subscription(
        user_id=new_user.id,
        plan="free",
        status="active",
        price_monthly=0.0,
        max_analyses_per_month=str(int(quota_free)),  # ← CORRIGÉ : utilise la config (12)
        current_analysis_count="0",
    )
    db.add(subscription)
    await db.flush()

    # Étape 4 : Générer et envoyer le code de vérification
    code = str(random.randint(100000, 999999))
    verification = EmailVerificationCode(
        email=user_data.email,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=15),
    )
    db.add(verification)
    await db.flush()

    send_verification_code(user_data.email, code, user_data.full_name or "")
    
    # Logger l'inscription
    logger.info(f"[AUTH] Nouvel utilisateur inscrit: {user_data.email}")

    return {
        "message": "Compte créé ! Un code de vérification a été envoyé à votre adresse email.",
        "email": user_data.email,
        "requires_verification": True,
    }


async def login_user(db: AsyncSession, login_data: UserLogin) -> TokenResponse:
    """
    Connecter un utilisateur existant - AUTH STATELESS.
    Étapes :
    1. Chercher l'utilisateur par email
    2. Vérifier le mot de passe
    3. Générer les tokens JWT (sans session_token DB)
    """
    # Étape 1 : Chercher l'utilisateur
    result = await db.execute(select(User).where(User.email == login_data.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
        )

    # Étape 2 : Vérifier le mot de passe
    if not user.hashed_password or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect",
        )

    # Vérifier que le compte est actif
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Votre compte a été désactivé.",
        )

    # Vérifier que l'email est vérifié (sauf comptes Google et admin)
    if not user.is_verified and user.auth_provider == "local" and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Veuillez d'abord vérifier votre adresse email.",
        )

    # Étape 3 : Auth stateless - juste mettre à jour last_login
    user.last_login = datetime.utcnow()
    await db.flush()
    
    # Logger la connexion réussie
    logger.info(f"[AUTH] Connexion réussie: {login_data.email} (role: {user.role})")

    # Étape 4 : Générer les tokens JWT stateless
    access_token = create_access_token(str(user.id), user.role)
    refresh_token = create_refresh_token(str(user.id))

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


async def refresh_tokens(db: AsyncSession, user_id: str) -> dict:
    """
    Rafraîchir les tokens JWT - STATELESS.
    Appelé quand le token d'accès expire.
    """
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur non trouvé ou désactivé",
        )

    # Auth stateless - pas de vérification session_token
    access_token = create_access_token(str(user.id), user.role)
    refresh_token = create_refresh_token(str(user.id))

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


async def get_user_profile(db: AsyncSession, user_id: UUID) -> User:
    """
    Récupérer le profil complet d'un utilisateur par son ID.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé",
        )

    return user