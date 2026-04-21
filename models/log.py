# === Modèle Journal (Logs) ===
# Enregistre toutes les actions importantes du système
# Utilisé pour l'audit, le debugging et la sécurité

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from database import Base
import enum


class LogLevel(str, enum.Enum):
    """Niveaux de gravité des logs"""
    INFO = "info"          # Information générale
    WARNING = "warning"    # Avertissement
    ERROR = "error"        # Erreur
    CRITICAL = "critical"  # Erreur critique


class LogCategory(str, enum.Enum):
    """Catégories de logs pour le filtrage"""
    AUTH = "auth"              # Authentification (connexion, inscription)
    ANALYSIS = "analysis"      # Analyses effectuées
    PAYMENT = "payment"        # Paiements et abonnements
    ADMIN = "admin"            # Actions administrateur
    SYSTEM = "system"          # Événements système
    SECURITY = "security"      # Événements de sécurité


class Log(Base):
    """
    Table 'logs' : journal de toutes les actions du système.
    - Permet de tracer les erreurs et les activités suspectes
    - Accessible uniquement aux administrateurs
    """
    __tablename__ = "logs"

    # --- Identifiant unique ---
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Utilisateur associé (optionnel) ---
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    # --- Détails du log ---
    level = Column(String(20), default=LogLevel.INFO.value)
    category = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)           # Description de l'événement
    details = Column(Text, nullable=True)            # Détails supplémentaires

    # --- Informations de contexte ---
    ip_address = Column(String(45), nullable=True)   # Adresse IP du client
    user_agent = Column(String(500), nullable=True)  # Navigateur du client
    endpoint = Column(String(255), nullable=True)    # Route API appelée

    # --- Date ---
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Log [{self.level}] {self.category}: {self.message[:50]}>"
