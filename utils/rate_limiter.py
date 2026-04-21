# === Limiteur de débit (Rate Limiting) ===
# Contrôle le nombre de requêtes par utilisateur et par IP
# Supporte Redis en production, fallback mémoire en développement
# Protège l'API contre les abus et les attaques par déni de service

from datetime import datetime
from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

# Stockage en mémoire des compteurs (fallback si Redis n'est pas disponible)
_rate_limits: dict = {}

# --- Connexion Redis (optionnelle) ---
_redis_client = None


async def get_redis():
    """
    Obtenir le client Redis.
    Tente de se connecter au démarrage, retourne None si indisponible.
    """
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    try:
        import redis.asyncio as aioredis
        from config import settings
        redis_url = getattr(settings, 'redis_url', None)
        if redis_url:
            _redis_client = aioredis.from_url(redis_url, decode_responses=True)
            # Tester la connexion
            await _redis_client.ping()
            return _redis_client
    except Exception:
        # Redis indisponible : utiliser le stockage mémoire
        _redis_client = None

    return None


class RateLimiter:
    """
    Classe de limitation de débit.
    - Vérifie le nombre d'analyses restantes selon le plan
    - Limite les requêtes par IP pour éviter les abus
    - Utilise Redis si disponible, sinon stockage en mémoire
    """

    @staticmethod
    async def get_limit_for_user(user, db: AsyncSession) -> int:
        """
        Obtenir la limite d'analyses pour un utilisateur.
        Utilise le quota individuel depuis la table subscriptions.
        """
        from services.config_helper import get_user_quota
        return await get_user_quota(user.id, db)

    @staticmethod
    async def check_analysis_limit(user, db: AsyncSession) -> bool:
        """
        Vérifier si l'utilisateur peut encore lancer une analyse.
        Compare le compteur d'analyses du mois avec la limite individuelle.
        Lève une erreur 429 si la limite est atteinte.
        """
        # Récupérer la limite individuelle de l'utilisateur
        limit = await RateLimiter.get_limit_for_user(user, db)

        # Récupérer le compteur actuel (gérer les types string/vide/null)
        try:
            current_count = int(user.monthly_analysis_count or 0)
        except (ValueError, TypeError):
            current_count = 0

        # Vérifier si la limite est atteinte
        if current_count >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Limite d'analyses atteinte ({limit}/mois). "
                       f"Passez à un plan supérieur pour continuer.",
            )

        return True

    @staticmethod
    async def check_ip_rate_limit(request: Request, max_requests: int = 60, window_seconds: int = 60):
        """
        Vérifier le nombre de requêtes par IP sur une fenêtre de temps.
        Par défaut : 60 requêtes par minute par IP.
        Utilise Redis si disponible, sinon le stockage mémoire.
        """
        client_ip = request.client.host if request.client else "unknown"
        key = f"rate_limit:ip:{client_ip}"

        # --- Tenter d'utiliser Redis ---
        redis = await get_redis()
        if redis:
            try:
                current = await redis.incr(key)
                # Définir l'expiration seulement à la première requête
                if current == 1:
                    await redis.expire(key, window_seconds)
                if current > max_requests:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Trop de requêtes. Veuillez réessayer dans quelques instants.",
                    )
                return
            except HTTPException:
                raise
            except Exception:
                pass  # Fallback vers le stockage mémoire

        # --- Fallback : stockage en mémoire ---
        now = datetime.utcnow()

        if key not in _rate_limits:
            _rate_limits[key] = {"count": 1, "reset_at": now}
        else:
            entry = _rate_limits[key]
            # Réinitialiser si la fenêtre est expirée
            elapsed = (now - entry["reset_at"]).total_seconds()
            if elapsed > window_seconds:
                _rate_limits[key] = {"count": 1, "reset_at": now}
            else:
                entry["count"] += 1
                if entry["count"] > max_requests:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Trop de requêtes. Veuillez réessayer dans quelques instants.",
                    )

    @staticmethod
    async def get_remaining_analyses(user, db: AsyncSession) -> dict:
        """
        Obtenir les informations sur les analyses restantes pour un utilisateur.
        Utile pour afficher dans le dashboard frontend.
        """
        limit = await RateLimiter.get_limit_for_user(user, db)
        try:
            current = int(user.monthly_analysis_count or 0)
        except (ValueError, TypeError):
            current = 0
        remaining = max(0, limit - current)

        return {
            "plan": user.role,
            "limit": limit,
            "used": current,
            "remaining": remaining,
            "percentage": round((current / limit) * 100, 1) if limit > 0 else 100,
        }