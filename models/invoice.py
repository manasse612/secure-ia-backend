# === Modèle Facture ===
# Gère les factures générées pour les abonnements payants
# Intégré avec Stripe pour la gestion automatique

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from database import Base
import enum


class InvoiceStatus(str, enum.Enum):
    """Statuts possibles d'une facture"""
    PENDING = "pending"        # En attente de paiement
    PAID = "paid"              # Payée
    FAILED = "failed"          # Paiement échoué
    REFUNDED = "refunded"      # Remboursée
    CANCELLED = "cancelled"    # Annulée


class Invoice(Base):
    """
    Table 'invoices' : stocke les factures des utilisateurs.
    - Générées automatiquement par Stripe à chaque paiement
    - Archivées au format PDF
    """
    __tablename__ = "invoices"

    # --- Identifiant unique ---
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Lien vers l'utilisateur ---
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # --- Détails de la facture ---
    amount = Column(Float, nullable=False)              # Montant en euros
    currency = Column(String(3), default="EUR")         # Devise
    description = Column(String(255), nullable=True)    # Description du paiement
    status = Column(String(20), default=InvoiceStatus.PENDING.value)

    # --- Intégration Stripe ---
    stripe_invoice_id = Column(String(255), nullable=True, unique=True)
    stripe_payment_intent_id = Column(String(255), nullable=True)
    pdf_url = Column(String(500), nullable=True)        # Lien vers le PDF Stripe

    # --- Période de facturation ---
    period_start = Column(DateTime, nullable=True)
    period_end = Column(DateTime, nullable=True)

    # --- Dates ---
    created_at = Column(DateTime, default=datetime.utcnow)
    paid_at = Column(DateTime, nullable=True)

    # --- Relation avec l'utilisateur ---
    user = relationship("User", back_populates="invoices")

    def __repr__(self):
        return f"<Invoice {self.amount}€ - {self.status}>"
