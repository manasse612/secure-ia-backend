# === Modèle Offre / Annonce ===
# Permet à l'admin de publier des offres visibles sur la page d'accueil
# Sans toucher au code, l'admin peut créer/modifier/supprimer des offres

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class Offer(Base):
    """
    Table 'offers' : offres et annonces publiées par l'admin.
    Affichées sur la page d'accueil et la page des tarifs.
    """
    __tablename__ = "offers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Contenu de l'offre
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    badge_text = Column(String(50), nullable=True)  # Ex: "Promo", "-50%", "Nouveau"
    badge_color = Column(String(20), default="primary")  # primary, green, red, orange

    # Image de l'offre (URL)
    image_url = Column(String(1000), nullable=True)

    # Lien optionnel (bouton CTA)
    cta_text = Column(String(100), nullable=True)  # Texte du bouton
    cta_link = Column(String(500), nullable=True)  # URL du bouton

    # Visibilité
    is_active = Column(Boolean, default=True)
    start_date = Column(DateTime, nullable=True)  # Date début (null = immédiat)
    end_date = Column(DateTime, nullable=True)    # Date fin (null = permanent)

    # Métadonnées
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Offer {self.title[:30]}>"
