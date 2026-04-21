# === Initialisation du module des modèles de base de données ===
# Importer tous les modèles ici pour qu'ils soient détectés par SQLAlchemy

from models.user import User
from models.subscription import Subscription
from models.analysis import Analysis
from models.api_usage import ApiUsage
from models.invoice import Invoice
from models.log import Log
from models.notification import Notification
from models.site_config import SiteConfig
from models.offer import Offer
from models.password_reset import PasswordResetCode
from models.email_verification import EmailVerificationCode

# Liste de tous les modèles exportés
__all__ = [
    "User",
    "Subscription",
    "Analysis",
    "ApiUsage",
    "Invoice",
    "Log",
    "Notification",
    "SiteConfig",
    "Offer",
    "PasswordResetCode",
    "EmailVerificationCode",
]
