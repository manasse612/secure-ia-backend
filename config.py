# === Configuration générale de l'application Secure IA ===
# Ce fichier charge toutes les variables d'environnement nécessaires

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """
    Classe de configuration principale.
    Charge automatiquement les variables depuis le fichier .env
    """

    # --- Nom de l'application ---
    app_name: str = "Secure IA"
    debug: bool = False  # Production mode

    # --- URLs de l'application ---
    app_url: str = "http://localhost:5173"  # Dev local
    backend_url: str = "http://localhost:8000"  # Dev local

    # --- Base de données PostgreSQL ---
    database_url: str = "postgresql+asyncpg://postgres:password@localhost:5432/secure_ia"
    database_url_sync: str = "postgresql://postgres:password@localhost:5432/secure_ia"

    # --- Cache Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- Authentification JWT ---
    secret_key: Optional[str] = None  # Défini dans .env ou généré aléatoirement
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # --- OAuth Google ---
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None

    # --- APIs externes ---
    hive_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None

    # --- Email SMTP ---
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "noreply@secure-ia.com"
    smtp_from_name: str = "Secure IA"

    # --- Stripe (paiement) ---
    stripe_secret_key: Optional[str] = None
    stripe_webhook_secret: Optional[str] = None
    stripe_price_pro: Optional[str] = None
    stripe_price_business: Optional[str] = None

    # --- CORS pour app mobile ---
    allowed_origins: list = [
        "http://localhost:5173",
        "http://localhost:3000",
        "capacitor://localhost",
        "http://localhost",
        "https://localhost",
        # IP locale pour l'app mobile
        "http://10.13.53.201:8000",
        "http://10.13.53.201",
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Générer une clé automatiquement si non définie
        if not self.secret_key:
            import secrets
            self.secret_key = secrets.token_urlsafe(64)
            if self.debug:
                print("[WARN] SECRET_KEY auto-générée pour dev local")
            else:
                print("[WARN] SECRET_KEY auto-générée pour production (définissez-en une fixe pour éviter les déconnexions)")

    class Config:
        # Charger les variables depuis le fichier .env
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


# Créer une instance unique de la configuration
settings = Settings()
