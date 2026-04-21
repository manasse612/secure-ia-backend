# === Helper de configuration du site ===
# Fournit des fonctions utilitaires pour lire la configuration
# depuis la table site_config en base de données

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from models.site_config import SiteConfig, DEFAULT_CONFIG
from models.subscription import Subscription
from database import get_db
from uuid import UUID


async def get_config_value(key: str, db: AsyncSession = None) -> str:
    """
    Récupérer une valeur de configuration depuis la base de données.
    Retourne la valeur par défaut si la clé n'existe pas.
    """
    if db is None:
        # Créer une session temporaire
        from database import async_session
        async with async_session() as db:
            return await _fetch_config(key, db)
    return await _fetch_config(key, db)


async def _fetch_config(key: str, db: AsyncSession) -> str:
    """Récupérer une config depuis la DB."""
    result = await db.execute(
        select(SiteConfig.value).where(SiteConfig.key == key)
    )
    value = result.scalar_one_or_none()
    if value is not None:
        return value
    # Retourner la valeur par défaut
    default = DEFAULT_CONFIG.get(key)
    return default["value"] if default else ""


async def get_plan_pricing(db: AsyncSession = None) -> dict:
    """Récupérer les prix des plans."""
    price_pro = await get_config_value("price_pro", db)
    price_business = await get_config_value("price_business", db)
    return {
        "free": 0.0,
        "pro": float(price_pro) if price_pro else 29.90,
        "business": float(price_business) if price_business else 99.90,
    }


async def get_plan_quotas(db: AsyncSession = None) -> dict:
    """Récupérer les quotas globaux des plans."""
    quota_free = await get_config_value("quota_free", db)
    quota_pro = await get_config_value("quota_pro", db)
    quota_business = await get_config_value("quota_business", db)
    return {
        "free": int(quota_free) if quota_free else 10,
        "pro": int(quota_pro) if quota_pro else 500,
        "business": int(quota_business) if quota_business else 5000,
        "admin": 99999,
    }


async def get_user_quota(user_id: UUID, db: AsyncSession) -> int:
    """
    Récupérer le quota spécifique d'un utilisateur depuis sa table subscriptions.
    """
    # Récupérer l'abonnement de l'utilisateur
    sub_result = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    subscription = sub_result.scalar_one_or_none()
    
    if not subscription:
        # Si pas d'abonnement, utiliser le quota global gratuit
        return int(await get_config_value("quota_free", db))
    
    # Retourner le quota individuel
    return int(subscription.max_analyses_per_month)


async def init_default_config(db: AsyncSession):
    """
    Initialiser les valeurs de configuration par défaut.
    Appelé au démarrage de l'application.
    N'écrase pas les valeurs existantes.
    """
    for key, config in DEFAULT_CONFIG.items():
        existing = await db.execute(
            select(SiteConfig).where(SiteConfig.key == key)
        )
        if existing.scalar_one_or_none() is None:
            new_config = SiteConfig(
                key=key,
                value=config["value"],
                description=config["description"],
            )
            db.add(new_config)
    await db.flush()


async def is_simulation_mode(db: AsyncSession = None) -> bool:
    """
    Vérifier si l'application est en mode simulation.
    Retourne toujours False en production (pas de simulation).
    """
    return False