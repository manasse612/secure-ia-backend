# === Utilitaires de sécurité ===
# Gère le hachage des mots de passe et la création/vérification des tokens JWT

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from config import settings
from database import get_db

# --- Configuration du hachage de mot de passe avec bcrypt ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Schéma d'authentification Bearer (token dans le header) ---
security_scheme = HTTPBearer()


def hash_password(password: str) -> str:
    """
    Hacher un mot de passe en clair avec bcrypt.
    Retourne le hash à stocker en base de données.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifier si un mot de passe en clair correspond au hash stocké.
    Retourne True si le mot de passe est correct.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user_id: str, role: str, session_token: str = None) -> str:
    """
    Créer un token JWT d'accès stateless.
    - Contient l'ID utilisateur et son rôle
    - Expire après ACCESS_TOKEN_EXPIRE_MINUTES (30 min par défaut)
    - Inclut session_token si fourni (pour session unique)
    """
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": str(user_id),        # Sujet : ID de l'utilisateur
        "role": role,                # Rôle de l'utilisateur
        "type": "access",           # Type de token
        "exp": expire,              # Date d'expiration
        "iat": datetime.utcnow(),   # Date de création
        "jti": str(datetime.utcnow().timestamp()),  # JWT ID unique pour revocation future
    }
    # Inclure session_token dans le payload si fourni (session unique)
    if session_token:
        payload["session_token"] = session_token
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(user_id: str) -> str:
    """
    Créer un token JWT de rafraîchissement.
    - Permet de renouveler le token d'accès sans se reconnecter
    - Expire après REFRESH_TOKEN_EXPIRE_DAYS (7 jours par défaut)
    """
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict:
    """
    Décoder et vérifier un token JWT.
    Lève une exception si le token est invalide ou expiré.
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
):
    """
    Dépendance FastAPI : récupérer l'utilisateur connecté à partir du token JWT.
    - Extrait le token du header Authorization
    - Décode le token et récupère l'utilisateur en base
    - Lève une erreur 401 si le token est invalide
    """
    # Importer ici pour éviter les imports circulaires
    from models.user import User

    # Décoder le token JWT
    payload = decode_token(credentials.credentials)
    user_id = payload.get("sub")

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide : identifiant utilisateur manquant",
        )

    # Chercher l'utilisateur dans la base de données
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur non trouvé",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé",
        )

    # Vérifier le session_token pour invalider les tokens JWT lors d'une déconnexion
    token_session = payload.get("session_token")
    if token_session and user.active_session_token:
        if token_session != user.active_session_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session invalide ou déconnectée. Veuillez vous reconnecter.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return user


async def get_admin_user(current_user=Depends(get_current_user)):
    """
    Dépendance FastAPI : vérifier que l'utilisateur est administrateur.
    Utilisé pour protéger les routes du back-office admin.
    """
    if current_user.role != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès réservé aux administrateurs",
        )
    return current_user
