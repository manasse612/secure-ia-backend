# === Modèle Code de vérification d'email ===
# Stocke les codes envoyés après inscription pour confirmer l'email
# Même pattern que PasswordResetCode

import uuid
from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, Boolean
from sqlalchemy.dialects.postgresql import UUID
from database import Base


class EmailVerificationCode(Base):
    """
    Table 'email_verification_codes' : codes de vérification d'email après inscription.
    - Un code à 6 chiffres envoyé par email
    - Expire après 15 minutes
    - Usage unique
    """
    __tablename__ = "email_verification_codes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, index=True)
    code = Column(String(6), nullable=False)
    is_used = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<EmailVerificationCode {self.email} - {self.code}>"

    @property
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self):
        return not self.is_used and not self.is_expired
