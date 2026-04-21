# === Service d'échange de tokens sécurisé ===
# Stocke temporairement les tokens côté serveur avec un code unique
# Évite l'exposition des JWT dans l'URL du callback OAuth

import uuid
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from config import settings

# --- Stockage Redis ou mémoire ---
_exchange_store: Dict[str, Dict[str, Any]] = {}


async def _get_redis():
    """Obtenir le client Redis si disponible."""
    try:
        import redis.asyncio as aioredis
        redis_url = getattr(settings, 'redis_url', None)
        if redis_url:
            client = aioredis.from_url(redis_url, decode_responses=True)
            await client.ping()
            return client
    except Exception:
        pass
    return None


async def store_tokens_for_exchange(
    access_token: str,
    refresh_token: str,
    user_id: str,
    expires_in_seconds: int = 60
) -> str:
    """
    Stocke les tokens et retourne un code d'échange unique.
    
    Args:
        access_token: Token JWT d'accès
        refresh_token: Token JWT de rafraîchissement
        user_id: ID de l'utilisateur
        expires_in_seconds: Durée de validité du code (défaut: 60s)
    
    Returns:
        Code d'échange unique (UUID)
    """
    exchange_code = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in_seconds)
    
    data = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user_id": user_id,
        "expires_at": expires_at.isoformat(),
        "used": False,
    }
    
    # Essayer Redis d'abord
    redis = await _get_redis()
    if redis:
        await redis.setex(
            f"token_exchange:{exchange_code}",
            expires_in_seconds,
            json.dumps(data)
        )
    else:
        # Fallback mémoire avec nettoyage automatique
        _exchange_store[exchange_code] = data
        # Nettoyer les entrées expirées
        _cleanup_expired_codes()
    
    return exchange_code


async def exchange_code_for_tokens(exchange_code: str) -> Optional[Dict[str, str]]:
    """
    Échange un code contre les tokens.
    Le code est supprimé après utilisation (one-time use).
    
    Args:
        exchange_code: Code d'échange
    
    Returns:
        Dict avec access_token et refresh_token, ou None si invalide
    """
    redis = await _get_redis()
    
    if redis:
        # Redis mode
        key = f"token_exchange:{exchange_code}"
        data_str = await redis.get(key)
        if not data_str:
            return None
        
        data = json.loads(data_str)
        
        # Vérifier expiration
        expires_at = datetime.fromisoformat(data["expires_at"])
        if datetime.utcnow() > expires_at:
            await redis.delete(key)
            return None
        
        # Supprimer immédiatement (one-time use)
        await redis.delete(key)
        
    else:
        # Mémoire mode
        data = _exchange_store.get(exchange_code)
        if not data:
            return None
        
        # Vérifier expiration
        expires_at = datetime.fromisoformat(data["expires_at"])
        if datetime.utcnow() > expires_at or data.get("used"):
            del _exchange_store[exchange_code]
            return None
        
        # Marquer comme utilisé et supprimer
        data["used"] = True
        del _exchange_store[exchange_code]
    
    return {
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "user_id": data["user_id"],
    }


def _cleanup_expired_codes():
    """Nettoyer les codes expirés du stockage mémoire."""
    now = datetime.utcnow()
    expired = [
        code for code, data in _exchange_store.items()
        if datetime.fromisoformat(data["expires_at"]) < now or data.get("used")
    ]
    for code in expired:
        del _exchange_store[code]
