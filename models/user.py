# === Modèle Utilisateur ===
# Représente un utilisateur dans la base de données Secure IA
# Chaque utilisateur a un rôle (public, pro, admin) et un plan d'abonnement

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import enum


class UserRole(str, enum.Enum):
    """Rôles possibles pour un utilisateur - alignés avec les plans"""
    FREE = "free"              # Grand public (gratuit)
    PRO = "pro"                # Professionnel (abonnement Pro)
    BUSINESS = "business"      # Entreprise (abonnement Business)
    ADMIN = "admin"            # Administrateur Secure IA


class AuthProvider(str, enum.Enum):
    """Méthodes d'authentification disponibles"""
    LOCAL = "local"            # Email + mot de passe
    GOOGLE = "google"          # OAuth Google


class User(Base):
    """
    Table 'users' : stocke les informations de chaque utilisateur.
    - id : identifiant unique (UUID)
    - email : adresse email unique
    - hashed_password : mot de passe haché avec bcrypt
    - role : rôle de l'utilisateur (free, pro, business, admin)
    - auth_provider : méthode d'inscription (local ou Google)
    """
    __tablename__ = "users"

    # --- Identifiant unique ---
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Informations personnelles ---
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=True)  # Null si OAuth

    # --- Rôle et statut ---
    role = Column(String(20), default=UserRole.FREE.value, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)

    # --- Méthode d'authentification ---
    auth_provider = Column(String(20), default=AuthProvider.LOCAL.value)
    google_id = Column(String(255), nullable=True, unique=True)

    # --- Préférences ---
    language = Column(String(10), default="fr")  # Langue préférée
    avatar_url = Column(String(500), nullable=True)

    # --- Compteur d'analyses (pour le plan gratuit) ---
    monthly_analysis_count = Column(String(10), default="0")
    monthly_reset_date = Column(DateTime, nullable=True)

    # --- Session unique (un seul appareil à la fois) ---
    active_session_token = Column(String(255), nullable=True)

    # --- Dates importantes ---
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    # --- Relations avec les autres tables ---
    subscription = relationship("Subscription", back_populates="user", uselist=False)
    analyses = relationship("Analysis", back_populates="user")
    invoices = relationship("Invoice", back_populates="user")

    def __repr__(self):
        return f"<User {self.email} ({self.role})>"
