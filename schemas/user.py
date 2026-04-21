# === Schémas de validation pour les utilisateurs ===
# Définit les formats de données pour l'inscription, la connexion et les réponses

from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
from uuid import UUID


class UserCreate(BaseModel):
    """Schéma pour l'inscription d'un nouvel utilisateur"""
    email: EmailStr                                    # Email valide obligatoire
    password: str = Field(..., min_length=8)           # Mot de passe (8 caractères min)
    full_name: Optional[str] = None                    # Nom complet (optionnel)
    language: Optional[str] = "fr"                     # Langue préférée


class UserLogin(BaseModel):
    """Schéma pour la connexion d'un utilisateur"""
    email: EmailStr                                    # Email de connexion
    password: str                                      # Mot de passe


class GoogleAuthRequest(BaseModel):
    """Schéma pour l'authentification via Google OAuth"""
    token: str                                         # Token Google ID


class UserResponse(BaseModel):
    """Schéma de réponse contenant les infos utilisateur (sans mot de passe)"""
    id: UUID
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    is_verified: bool
    auth_provider: str
    language: str
    avatar_url: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True  # Permet la conversion depuis un objet SQLAlchemy


class UserUpdate(BaseModel):
    """Schéma pour la mise à jour du profil utilisateur"""
    full_name: Optional[str] = None
    language: Optional[str] = None
    avatar_url: Optional[str] = None


class PasswordChange(BaseModel):
    """Schéma pour le changement de mot de passe"""
    current_password: str                              # Mot de passe actuel
    new_password: str = Field(..., min_length=8)       # Nouveau mot de passe


class TokenResponse(BaseModel):
    """Schéma de réponse contenant les tokens JWT"""
    access_token: str                                  # Token d'accès
    refresh_token: str                                 # Token de rafraîchissement
    token_type: str = "bearer"                         # Type de token
    user: UserResponse                                 # Infos utilisateur
