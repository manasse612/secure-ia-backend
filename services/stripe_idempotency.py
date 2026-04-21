# === Service d'Idempotence Stripe ===
# Évite le traitement multiple d'un même événement webhook
# Protège contre les doubles paiements et mises à jour

import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Stockage mémoire pour le fallback
_processed_events: Dict[str, Dict[str, Any]] = {}


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


def _extract_event_id(event: Dict[str, Any]) -> Optional[str]:
    """Extraire l'ID unique de l'événement Stripe."""
    # L'ID de l'événement Stripe est dans event['id']
    return event.get("id")


def _extract_idempotency_key(event: Dict[str, Any]) -> Optional[str]:
    """
    Extraire la clé d'idempotence si présente.
    Stripe peut envoyer une clé idempotence dans les headers de la requête originale.
    """
    # Vérifier dans le payload de l'événement
    session = event.get("data", {}).get("object", {})
    return session.get("idempotency_key")


async def is_event_processed(event: Dict[str, Any]) -> bool:
    """
    Vérifier si un événement a déjà été traité.
    
    Args:
        event: L'événement Stripe
    
    Returns:
        True si l'événement a déjà été traité
    """
    event_id = _extract_event_id(event)
    if not event_id:
        return False
    
    redis = await _get_redis()
    
    if redis:
        # Vérifier dans Redis
        key = f"stripe:processed:{event_id}"
        exists = await redis.exists(key)
        return bool(exists)
    else:
        # Vérifier dans la mémoire
        if event_id in _processed_events:
            # Nettoyer les entrées expirées
            _cleanup_expired_events()
            entry = _processed_events[event_id]
            expires_at = entry.get("expires_at")
            if expires_at and datetime.utcnow() > expires_at:
                del _processed_events[event_id]
                return False
            return True
        return False


async def mark_event_processed(event: Dict[str, Any], result: Optional[Dict] = None) -> None:
    """
    Marquer un événement comme traité.
    
    Args:
        event: L'événement Stripe
        result: Résultat du traitement (optionnel)
    """
    event_id = _extract_event_id(event)
    if not event_id:
        return
    
    redis = await _get_redis()
    expires_in_seconds = 86400  # 24 heures de rétention
    
    data = {
        "processed_at": datetime.utcnow().isoformat(),
        "event_type": event.get("type"),
        "result": result,
    }
    
    if redis:
        key = f"stripe:processed:{event_id}"
        await redis.setex(key, expires_in_seconds, json.dumps(data))
    else:
        _processed_events[event_id] = {
            "data": data,
            "expires_at": datetime.utcnow() + timedelta(seconds=expires_in_seconds),
        }


def _cleanup_expired_events():
    """Nettoyer les événements expirés du stockage mémoire."""
    now = datetime.utcnow()
    expired = [
        event_id for event_id, entry in _processed_events.items()
        if entry.get("expires_at") and entry["expires_at"] < now
    ]
    for event_id in expired:
        del _processed_events[event_id]


async def get_event_processing_result(event: Dict[str, Any]) -> Optional[Dict]:
    """
    Récupérer le résultat d'un traitement précédent.
    Utile pour renvoyer la même réponse en cas de retry.
    """
    event_id = _extract_event_id(event)
    if not event_id:
        return None
    
    redis = await _get_redis()
    
    if redis:
        key = f"stripe:processed:{event_id}"
        data_str = await redis.get(key)
        if data_str:
            return json.loads(data_str)
    else:
        entry = _processed_events.get(event_id)
        if entry:
            return entry.get("data")
    
    return None
