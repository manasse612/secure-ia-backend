# === Modèle Utilisation API ===
# Suit la consommation des APIs externes (Hive AI, OpenAI, VirusTotal)
# Permet de surveiller les coûts et d'alerter en cas de dépassement

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Float, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from database import Base
import enum


class ApiProvider(str, enum.Enum):
    """Fournisseurs d'APIs externes utilisés par Secure IA"""
    HIVE = "hive"                # Détection deepfake & IA (images, vidéos) via Hive AI
    OPENAI = "openai"            # Fact-checking, analyse sémantique
    VIRUSTOTAL = "virustotal"    # Scan URLs, réputation sites
    STRIPE = "stripe"            # Gestion des paiements


class ApiUsage(Base):
    """
    Table 'api_usage' : enregistre chaque appel API externe.
    - Permet de calculer les coûts mensuels
    - Utilisé dans le dashboard admin pour le monitoring
    """
    __tablename__ = "api_usage"

    # --- Identifiant unique ---
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Lien vers l'analyse associée ---
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("analyses.id"), nullable=True)

    # --- Fournisseur API ---
    provider = Column(String(50), nullable=False)
    endpoint = Column(String(255), nullable=True)  # Point d'entrée API appelé

    # --- Détails de l'appel ---
    request_tokens = Column(Integer, default=0)    # Tokens envoyés (OpenAI)
    response_tokens = Column(Integer, default=0)   # Tokens reçus (OpenAI)
    cost = Column(Float, default=0.0)              # Coût estimé en euros

    # --- Statut de l'appel ---
    status_code = Column(Integer, nullable=True)    # Code HTTP de la réponse
    response_time_ms = Column(Float, nullable=True)  # Temps de réponse en ms
    error_message = Column(String(500), nullable=True)  # Message d'erreur si échec

    # --- Date de l'appel ---
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<ApiUsage {self.provider} - {self.cost}€>"
