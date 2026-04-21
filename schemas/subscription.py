# === Schémas de validation pour les abonnements ===
# Définit les formats de données pour les plans et la facturation

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID


class SubscriptionResponse(BaseModel):
    """Schéma de réponse pour les informations d'abonnement"""
    id: UUID
    plan: str                                  # Type de plan (free, pro, business)
    status: str                                # Statut de l'abonnement
    price_monthly: float                       # Prix mensuel
    max_analyses_per_month: str                # Limite mensuelle
    current_analysis_count: str                # Analyses utilisées ce mois
    start_date: datetime
    end_date: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class SubscriptionUpdate(BaseModel):
    """Schéma pour changer de plan d'abonnement"""
    plan: str                                  # Nouveau plan souhaité


class CheckoutSessionRequest(BaseModel):
    """Schéma pour créer une session de paiement Stripe"""
    plan: str                                  # Plan choisi (pro ou business)
    billing_period: str = "monthly"            # Mensuel ou annuel


class CheckoutSessionResponse(BaseModel):
    """Schéma de réponse avec l'URL de paiement Stripe"""
    checkout_url: str                          # URL vers la page de paiement
    session_id: str                            # ID de la session Stripe
