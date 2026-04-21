# === Modèle Analyse ===
# Stocke les résultats de chaque analyse effectuée par un utilisateur
# Les données sensibles (input_data, result) sont chiffrées en base
# Types d'analyses : image, texte, URL, vidéo

import uuid
import json
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Float, Text, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
from utils.encryption import EncryptedString
import enum


class AnalysisType(str, enum.Enum):
    """Types d'analyses disponibles sur la plateforme"""
    IMAGE = "image"        # Analyse d'image (détection IA, métadonnées)
    TEXT = "text"          # Analyse de texte (fact-checking, NLP)
    URL = "url"            # Analyse d'URL (sécurité, réputation)
    VIDEO = "video"        # Analyse vidéo (deepfake) - Pro uniquement


class AnalysisStatus(str, enum.Enum):
    """Statuts possibles d'une analyse"""
    PENDING = "pending"        # En attente de traitement
    PROCESSING = "processing"  # En cours d'analyse
    COMPLETED = "completed"    # Analyse terminée
    FAILED = "failed"          # Échec de l'analyse
    CANCELLED = "cancelled"    # Annulée par l'utilisateur


class Analysis(Base):
    """
    Table 'analyses' : enregistre chaque analyse effectuée.
    - input_data : le contenu soumis (URL, texte, chemin fichier)
    - result : résultats détaillés au format JSON
    - score : score d'authenticité de 0 à 100
    """
    __tablename__ = "analyses"

    # --- Identifiant unique ---
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Lien vers l'utilisateur ---
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # --- Type et statut de l'analyse ---
    analysis_type = Column(String(20), nullable=False)
    status = Column(String(20), default=AnalysisStatus.PENDING.value)

    # --- Données d'entrée (chiffrées) ---
    _input_data_encrypted = Column("input_data", Text, nullable=False)
    input_filename = Column(String(255), nullable=True)  # Nom du fichier uploadé
    input_mime_type = Column(String(100), nullable=True)  # Type MIME du fichier

    # --- Résultats de l'analyse ---
    score = Column(Float, nullable=True)               # Score d'authenticité (0-100)
    verdict = Column(String(50), nullable=True)         # Verdict : vrai, faux, non vérifiable
    _result_data = Column("result", JSON, nullable=True)  # Résultats détaillés (JSONB en DB)
    summary = Column(Text, nullable=True)               # Résumé en langage naturel

    @property
    def input_data(self):
        """Déchiffrer automatiquement input_data à la lecture."""
        if self._input_data_encrypted is None:
            return None
        try:
            return EncryptedString.decrypt(self._input_data_encrypted)
        except ValueError:
            # Rétrocompatibilité: données non chiffrées
            return self._input_data_encrypted

    @input_data.setter
    def input_data(self, value):
        """Chiffrer automatiquement input_data avant stockage."""
        if value is not None:
            self._input_data_encrypted = EncryptedString.encrypt(str(value))
        else:
            self._input_data_encrypted = None

    @property
    def result(self):
        """Récupérer les résultats JSON."""
        return self._result_data

    @result.setter
    def result(self, value):
        """Stocker les résultats JSON."""
        self._result_data = value

    # --- APIs utilisées ---
    apis_called = Column(JSON, nullable=True)           # Liste des APIs appelées
    api_costs = Column(Float, default=0.0)              # Coût total des appels API

    # --- Métadonnées ---
    processing_time_ms = Column(Float, nullable=True)   # Temps de traitement en ms
    pdf_report_url = Column(String(500), nullable=True)  # Lien vers le rapport PDF

    # --- Dates ---
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # --- Relation avec l'utilisateur ---
    user = relationship("User", back_populates="analyses")

    def __repr__(self):
        return f"<Analysis {self.analysis_type} - Score: {self.score}>"
