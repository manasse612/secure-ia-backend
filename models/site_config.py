# === Modèle Configuration du site ===
# Stocke les paramètres globaux modifiables par l'admin
# Mode simulation, prix des plans, quotas, etc.

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Boolean, Float
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class SiteConfig(Base):
    """
    Table 'site_config' : paramètres globaux du site.
    Clé-valeur simple, modifiable par l'admin sans toucher au code.
    """
    __tablename__ = "site_config"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=False)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<SiteConfig {self.key}={self.value}>"


# Valeurs par défaut à insérer au premier lancement
DEFAULT_CONFIG = {
    "price_pro": {
        "value": "29.90",
        "description": "Prix mensuel du plan Pro en euros"
    },
    "price_business": {
        "value": "99.90",
        "description": "Prix mensuel du plan Business en euros"
    },
    "quota_free": {
        "value": "10",
        "description": "Nombre d'analyses par mois pour le plan gratuit"
    },
    "quota_pro": {
        "value": "500",
        "description": "Nombre d'analyses par mois pour le plan Pro"
    },
    "quota_business": {
        "value": "5000",
        "description": "Nombre d'analyses par mois pour le plan Business"
    },
    "stripe_enabled": {
        "value": "false",
        "description": "Activer les paiements Stripe réels (sinon simulation)"
    },
}
