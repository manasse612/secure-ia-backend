# === Schémas de validation pour les analyses ===
# Définit les formats de données pour les requêtes et réponses d'analyse

from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID


class AnalysisRequest(BaseModel):
    """Schéma pour lancer une nouvelle analyse"""
    analysis_type: str = Field(..., description="Type : image, text, url, video")
    input_data: str = Field(..., description="Contenu à analyser (URL, texte, etc.)")
    input_filename: Optional[str] = None  # Nom du fichier si upload


class ImageAnalysisRequest(BaseModel):
    """Schéma spécifique pour l'analyse d'image"""
    image_url: Optional[str] = None       # URL de l'image à analyser
    # Le fichier uploadé est géré séparément via multipart/form-data


class TextAnalysisRequest(BaseModel):
    """Schéma spécifique pour l'analyse de texte"""
    text: str = Field(..., min_length=10, max_length=10000)  # Texte à vérifier
    language: Optional[str] = "fr"         # Langue du texte


class UrlAnalysisRequest(BaseModel):
    """Schéma spécifique pour l'analyse d'URL"""
    url: str = Field(..., description="URL du site web à analyser")


class AnalysisResponse(BaseModel):
    """Schéma de réponse pour une analyse terminée"""
    id: UUID
    analysis_type: str
    status: str
    input_data: str
    input_filename: Optional[str] = None
    score: Optional[float] = None          # Score d'authenticité (0-100)
    verdict: Optional[str] = None          # Verdict final
    result: Optional[Any] = None           # Résultats détaillés (JSON)
    summary: Optional[str] = None          # Résumé en langage naturel
    processing_time_ms: Optional[float] = None
    pdf_report_url: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AnalysisListResponse(BaseModel):
    """Schéma de réponse pour la liste des analyses (historique)"""
    analyses: List[AnalysisResponse]       # Liste des analyses
    total: int                              # Nombre total d'analyses
    page: int                               # Page actuelle
    per_page: int                           # Nombre par page
