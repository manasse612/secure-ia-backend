# === Modèle Code de réinitialisation de mot de passe ===
# Stocke les codes de vérification envoyés par email
# Permet la récupération sécurisée du mot de passe

import uuid
from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class PasswordResetCode(Base):
    """
    Table 'password_reset_codes' : codes de vérification pour reset de mot de passe.
    - Un code à 6 chiffres envoyé par email
    - Expire après 15 minutes
    - Usage unique
    """
    __tablename__ = "password_reset_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, index=True)
    code = Column(String(6), nullable=False)
    is_used = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<PasswordResetCode {self.email} - {self.code}>"

    @property
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired
