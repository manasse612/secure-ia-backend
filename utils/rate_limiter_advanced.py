# === Rate Limiting Avancé ===
# Protection contre les attaques DDoS et le spam sur les endpoints critiques
# Combine Redis (production) et mémoire (développement)

import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
from fastapi import HTTPException, Request, status
from functools import wraps

# Stockage mémoire pour le fallback
_request_history: Dict[str, Dict] = {}
_lock = asyncio.Lock()


async def _get_redis():
    """Obtenir le client Redis si disponible."""
    try:
        import redis.asyncio as aioredis
        from config import settings
        redis_url = getattr(settings, 'redis_url', None)
        if redis_url:
            client = aioredis.from_url(redis_url, decode_responses=True)
            await client.ping()
            return client
    except Exception:
        pass
    return None


def _get_client_ip(request: Request) -> str:
    """Extraire l'IP réelle du client (prend en compte les proxies)."""
    # Vérifier les headers de proxy
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Prendre la première IP (client original)
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    return request.client.host if request.client else "unknown"


class AdvancedRateLimiter:
    """
    Rate limiter avancé avec plusieurs niveaux de protection.
    
    Niveaux:
    1. Global par IP (protection DDoS)
    2. Par endpoint par IP (protection spam)
    3. Par utilisateur (protection abus de compte)
    """
    
    # --- Limites par défaut ---
    DEFAULT_LIMITS = {
        # Protection DDoS globale par IP
        "global_per_ip": {"requests": 100, "window": 60},  # 100 req/min par IP
        
        # Endpoints d'analyse (coûteux en ressources)
        "analysis_per_ip": {"requests": 100, "window": 60},   # 100 analyses/min par IP (dev: 100, prod: 10)
        "analysis_per_user": {"requests": 100, "window": 60},  # 100 analyses/min par user (dev: 100, prod: 30)
        
        # Authentification (protéger contre brute force)
        "auth_per_ip": {"requests": 5, "window": 60},        # 5 tentatives/min par IP
        "auth_global": {"requests": 20, "window": 60},     # 20 tentatives/min global
        
        # Upload de fichiers
        "upload_per_ip": {"requests": 5, "window": 60},     # 5 uploads/min par IP
        "upload_size": {"bytes": 50 * 1024 * 1024},          # 50 Mo/min par IP
    }
    
    @staticmethod
    async def check_limit(
        request: Request,
        limit_type: str,
        user_id: Optional[str] = None,
        custom_limits: Optional[Dict] = None
    ) -> bool:
        """
        Vérifier si une requête respecte les limites.
        
        Args:
            request: Requête FastAPI
            limit_type: Type de limite (clé dans DEFAULT_LIMITS)
            user_id: ID utilisateur (optionnel, pour les limites par user)
            custom_limits: Limite personnalisée (optionnel)
        
        Returns:
            True si autorisé, lève HTTPException 429 sinon
        """
        limits = custom_limits or AdvancedRateLimiter.DEFAULT_LIMITS.get(limit_type)
        if not limits:
            return True
        
        client_ip = _get_client_ip(request)
        now = datetime.utcnow()
        
        # Construire la clé de rate limit
        if user_id and "per_user" in limit_type:
            key = f"ratelimit:{limit_type}:user:{user_id}"
        else:
            key = f"ratelimit:{limit_type}:ip:{client_ip}"
        
        redis = await _get_redis()
        
        if redis:
            # Mode Redis (production)
            return await AdvancedRateLimiter._check_redis_limit(
                redis, key, limits, limit_type
            )
        else:
            # Mode mémoire (développement)
            return await AdvancedRateLimiter._check_memory_limit(
                key, limits, limit_type, now
            )
    
    @staticmethod
    async def _check_redis_limit(
        redis, key: str, limits: Dict, limit_type: str
    ) -> bool:
        """Vérifier la limite avec Redis."""
        window = limits.get("window", 60)
        max_requests = limits.get("requests", 100)
        
        # Incrémenter le compteur
        current = await redis.incr(key)
        
        # Définir l'expiration à la première requête
        if current == 1:
            await redis.expire(key, window)
        
        # Vérifier la limite
        if current > max_requests:
            ttl = await redis.ttl(key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Trop de requêtes",
                    "limit_type": limit_type,
                    "retry_after": ttl,
                    "message": f"Limite de {max_requests} requêtes par {window} secondes atteinte. "
                              f"Réessayez dans {ttl} secondes."
                },
            )
        
        return True
    
    @staticmethod
    async def _check_memory_limit(
        key: str, limits: Dict, limit_type: str, now: datetime
    ) -> bool:
        """Vérifier la limite avec stockage mémoire."""
        async with _lock:
            window = limits.get("window", 60)
            max_requests = limits.get("requests", 100)
            
            if key not in _request_history:
                _request_history[key] = {
                    "count": 1,
                    "reset_at": now,
                }
                return True
            
            entry = _request_history[key]
            elapsed = (now - entry["reset_at"]).total_seconds()
            
            # Réinitialiser si la fenêtre est expirée
            if elapsed > window:
                _request_history[key] = {
                    "count": 1,
                    "reset_at": now,
                }
                return True
            
            # Incrémenter et vérifier
            entry["count"] += 1
            if entry["count"] > max_requests:
                retry_after = int(window - elapsed)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Trop de requêtes",
                        "limit_type": limit_type,
                        "retry_after": retry_after,
                        "message": f"Limite de {max_requests} requêtes par {window} secondes atteinte. "
                                  f"Réessayez dans {retry_after} secondes."
                    },
                )
            
            return True
    
    @staticmethod
    async def check_upload_size(request: Request, file_size: int) -> bool:
        """
        Vérifier la limite de taille d'upload par IP.
        """
        client_ip = _get_client_ip(request)
        key = f"ratelimit:upload_size:ip:{client_ip}"
        limit_bytes = AdvancedRateLimiter.DEFAULT_LIMITS["upload_size"]["bytes"]
        window = 60  # 1 minute
        
        redis = await _get_redis()
        
        if redis:
            # Redis: utiliser un compteur pour les bytes
            current = await redis.incrby(key, file_size)
            if current == file_size:  # Première requête
                await redis.expire(key, window)
            
            if current > limit_bytes:
                ttl = await redis.ttl(key)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Quota d'upload dépassé",
                        "retry_after": ttl,
                        "message": f"Limite de {limit_bytes / (1024*1024):.0f} Mo d'upload par minute atteinte."
                    }
                )
        else:
            # Mémoire
            async with _lock:
                now = datetime.utcnow()
                if key not in _request_history:
                    _request_history[key] = {
                        "count": file_size,  # Utilisé comme bytes total
                        "reset_at": now,
                    }
                else:
                    entry = _request_history[key]
                    elapsed = (now - entry["reset_at"]).total_seconds()
                    if elapsed > window:
                        entry["count"] = file_size
                        entry["reset_at"] = now
                    else:
                        entry["count"] += file_size
                    
                    if entry["count"] > limit_bytes:
                        retry_after = int(window - elapsed)
                        raise HTTPException(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail={
                                "error": "Quota d'upload dépassé",
                                "retry_after": retry_after,
                                "message": f"Limite de {limit_bytes / (1024*1024):.0f} Mo d'upload par minute atteinte."
                            }
                        )
        
        return True


def require_rate_limit(limit_type: str):
    """
    Décorateur pour appliquer un rate limit sur une route.
    
    Usage:
        @router.post("/analysis")
        @require_rate_limit("analysis_per_ip")
        async def analyze(...):
            ...
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Trouver request dans les arguments
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                for v in kwargs.values():
                    if isinstance(v, Request):
                        request = v
                        break
            
            if request:
                await AdvancedRateLimiter.check_limit(request, limit_type)
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator
