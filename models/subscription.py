# === Modèle Abonnement ===
# Gère les plans d'abonnement des utilisateurs (Free, Pro, Business, Enterprise)

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import enum


class PlanType(str, enum.Enum):
    """Types de plans disponibles"""
    FREE = "free"              # Gratuit : 10 analyses/mois
    PRO = "pro"                # Pro : 500 analyses/mois, 29.90€
    BUSINESS = "business"      # Business : 5000 analyses/mois, 99.90€
    ENTERPRISE = "enterprise"  # Enterprise : sur devis


class SubscriptionStatus(str, enum.Enum):
    """Statuts possibles d'un abonnement"""
    ACTIVE = "active"          # Abonnement actif
    CANCELLED = "cancelled"    # Annulé (reste actif jusqu'à fin de période)
    EXPIRED = "expired"        # Expiré
    PAST_DUE = "past_due"     # Paiement en retard
    TRIALING = "trialing"      # Période d'essai


class Subscription(Base):
    """
    Table 'subscriptions' : stocke les abonnements des utilisateurs.
    - Chaque utilisateur a un seul abonnement actif
    - Lié à Stripe via stripe_customer_id et stripe_subscription_id
    """
    __tablename__ = "subscriptions"

    # --- Identifiant unique ---
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Lien vers l'utilisateur ---
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), unique=True, nullable=False)

    # --- Détails du plan ---
    plan = Column(String(20), default=PlanType.FREE.value, nullable=False)
    status = Column(String(20), default=SubscriptionStatus.ACTIVE.value)
    price_monthly = Column(Float, default=0.0)  # Prix mensuel en euros

    # --- Limites du plan ---
    max_analyses_per_month = Column(String(10), nullable=False, default="10")  # ← DEFAULT ajouté
    current_analysis_count = Column(String(10), default="0")   # Compteur actuel

    # --- Intégration Stripe ---
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)

    # --- Dates ---
    start_date = Column(DateTime, default=datetime.utcnow)
    end_date = Column(DateTime, nullable=True)       # Date de fin prévue
    cancelled_at = Column(DateTime, nullable=True)    # Date d'annulation
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # --- Relation avec l'utilisateur ---
    user = relationship("User", back_populates="subscription")

    def __repr__(self):
        return f"<Subscription {self.plan} - {self.status}>"