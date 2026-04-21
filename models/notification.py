# === Modèle Notification ===
# Gère les notifications envoyées par l'admin aux utilisateurs
# Permet d'informer les utilisateurs de changements, alertes, etc.

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class Notification(Base):
    """
    Table 'notifications' : notifications envoyées aux utilisateurs.
    - Peut cibler un utilisateur spécifique ou tous les utilisateurs (user_id = NULL)
    - L'admin peut envoyer des messages personnalisés
    """
    __tablename__ = "notifications"

    # --- Identifiant unique ---
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # --- Destinataire (NULL = notification globale à tous) ---
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)

    # --- Contenu ---
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    type = Column(String(20), default="info")  # info, warning, success, error

    # --- État ---
    is_read = Column(Boolean, default=False)

    # --- Dates ---
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.title[:30]}>"
