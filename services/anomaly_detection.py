# === Service de Détection d'Anomalies ===
# Détecte les comportements suspects et les attaques potentielles
# Alerte les administrateurs en cas d'activité anormale

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import json


class AnomalyType(Enum):
    """Types d'anomalies détectables."""
    RATE_LIMIT_VIOLATION = "rate_limit_violation"  # Trop de requêtes
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"    # Tentatives de connexion multiples
    UNUSUAL_ANALYSIS_PATTERN = "unusual_analysis_pattern"  # Pattern d'analyse suspect
    LARGE_UPLOAD_VOLUME = "large_upload_volume"   # Volume d'upload anormal
    ADMIN_ESCALATION_ATTEMPT = "admin_escalation_attempt"  # Tentative élévation privilèges
    DATA_EXFILTRATION = "data_exfiltration"        # Extraction massive de données
    GEO_ANOMALY = "geo_anomaly"                     # Connexion depuis localisation suspecte
    TIME_ANOMALY = "time_anomaly"                  # Activité à des heures inhabituelles


@dataclass
class AnomalyEvent:
    """Événement d'anomalie détectée."""
    type: AnomalyType
    severity: str  # low, medium, high, critical
    user_id: Optional[str]
    ip_address: Optional[str]
    description: str
    details: Dict[str, Any]
    timestamp: datetime


class AnomalyDetector:
    """
    Détecteur d'anomalies basé sur des règles et des seuils.
    """
    
    # --- Seuils de détection ---
    THRESHOLDS = {
        "login_attempts_per_minute": 5,      # Max 5 tentatives/min
        "analyses_per_minute": 20,            # Max 20 analyses/min
        "failed_logins_per_hour": 10,         # Max 10 échecs/heure
        "download_volume_per_hour": 100,      # Max 100 exports/heure
        "upload_volume_mb_per_hour": 500,     # Max 500 Mo upload/heure
        "admin_actions_per_minute": 10,       # Max 10 actions admin/min
        "account_changes_per_day": 5,         # Max 5 changements/jour
    }
    
    # Stockage en mémoire des événements récents (fallback si Redis indisponible)
    _events: Dict[str, List[datetime]] = {}
    _anomalies: List[AnomalyEvent] = []
    
    @staticmethod
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
    
    @classmethod
    async def record_event(cls, event_type: str, user_id: Optional[str] = None, 
                          ip_address: Optional[str] = None, details: Optional[Dict] = None):
        """Enregistrer un événement pour analyse."""
        now = datetime.utcnow()
        key = f"event:{event_type}:{user_id or ip_address or 'anonymous'}"
        
        redis = await cls._get_redis()
        if redis:
            # Ajouter à une liste Redis avec expiration
            await redis.lpush(key, now.isoformat())
            await redis.ltrim(key, 0, 999)  # Garder les 1000 derniers
            await redis.expire(key, 86400)  # Expire après 24h
        else:
            # Stockage mémoire
            if key not in cls._events:
                cls._events[key] = []
            cls._events[key].append(now)
            # Nettoyer les vieux événements
            cls._events[key] = [
                t for t in cls._events[key]
                if (now - t).total_seconds() < 86400
            ][:1000]
    
    @classmethod
    async def check_brute_force(cls, ip_address: str, user_id: Optional[str] = None) -> Optional[AnomalyEvent]:
        """Détecter les tentatives de brute force sur l'authentification."""
        key = f"event:login_failed:{user_id or ip_address}"
        
        redis = await cls._get_redis()
        now = datetime.utcnow()
        window = timedelta(minutes=10)
        
        if redis:
            events_raw = await redis.lrange(key, 0, -1)
            events = [datetime.fromisoformat(e) for e in events_raw]
        else:
            events = cls._events.get(key, [])
        
        # Compter les événements récents
        recent_events = [e for e in events if (now - e) < window]
        
        if len(recent_events) >= cls.THRESHOLDS["login_attempts_per_minute"]:
            return AnomalyEvent(
                type=AnomalyType.BRUTE_FORCE_ATTEMPT,
                severity="high" if len(recent_events) > 20 else "medium",
                user_id=user_id,
                ip_address=ip_address,
                description=f"{len(recent_events)} tentatives de connexion échouées en 10 minutes",
                details={"attempts": len(recent_events), "window_minutes": 10},
                timestamp=now
            )
        return None
    
    @classmethod
    async def check_analysis_spam(cls, user_id: str, ip_address: str) -> Optional[AnomalyEvent]:
        """Détecter les attaques par spam sur les analyses."""
        key = f"event:analysis_completed:{user_id}"
        
        redis = await cls._get_redis()
        now = datetime.utcnow()
        window = timedelta(minutes=1)
        
        if redis:
            events_raw = await redis.lrange(key, 0, -1)
            events = [datetime.fromisoformat(e) for e in events_raw]
        else:
            events = cls._events.get(key, [])
        
        recent_events = [e for e in events if (now - e) < window]
        
        if len(recent_events) >= cls.THRESHOLDS["analyses_per_minute"]:
            return AnomalyEvent(
                type=AnomalyType.RATE_LIMIT_VIOLATION,
                severity="high",
                user_id=user_id,
                ip_address=ip_address,
                description=f"{len(recent_events)} analyses en 1 minute (possible DDoS)",
                details={"analyses_count": len(recent_events), "window_minutes": 1},
                timestamp=now
            )
        return None
    
    @classmethod
    async def check_large_data_extraction(cls, user_id: str) -> Optional[AnomalyEvent]:
        """Détecter les tentatives d'extraction massive de données."""
        key = f"event:pdf_export:{user_id}"
        
        redis = await cls._get_redis()
        now = datetime.utcnow()
        window = timedelta(hours=1)
        
        if redis:
            events_raw = await redis.lrange(key, 0, -1)
            events = [datetime.fromisoformat(e) for e in events_raw]
        else:
            events = cls._events.get(key, [])
        
        recent_exports = len([e for e in events if (now - e) < window])
        
        if recent_exports >= cls.THRESHOLDS["download_volume_per_hour"]:
            return AnomalyEvent(
                type=AnomalyType.DATA_EXFILTRATION,
                severity="critical",
                user_id=user_id,
                ip_address=None,
                description=f"{recent_exports} exports PDF en 1 heure (extraction massive)",
                details={"exports_count": recent_exports, "window_hours": 1},
                timestamp=now
            )
        return None
    
    @classmethod
    async def report_anomaly(cls, event: AnomalyEvent) -> None:
        """Signaler une anomalie détectée."""
        cls._anomalies.append(event)
        
        # Logger l'anomalie
        import logging
        logger = logging.getLogger(__name__)
        
        log_message = (
            f"[ANOMALIE {event.severity.upper()}] {event.type.value}: "
            f"{event.description} | User: {event.user_id} | IP: {event.ip_address}"
        )
        
        if event.severity == "critical":
            logger.critical(log_message)
        elif event.severity == "high":
            logger.error(log_message)
        elif event.severity == "medium":
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        # TODO: Envoyer une notification aux administrateurs
        # TODO: Stocker dans une table d'anomalies pour le dashboard admin
        # TODO: Bloquer automatiquement l'IP si trop d'anomalies
        
        # Envoyer une notification admin en temps réel (WebSocket ou email)
        if event.severity in ["high", "critical"]:
            await cls._notify_admins(event)
    
    @classmethod
    async def _notify_admins(cls, event: AnomalyEvent) -> None:
        """Notifier les administrateurs d'une anomalie critique."""
        # Cette méthode peut être connectée à un service de notification
        # Par exemple: email, Slack, ou notification dans l'admin panel
        pass
    
    @classmethod
    def get_recent_anomalies(cls, minutes: int = 60) -> List[AnomalyEvent]:
        """Récupérer les anomalies récentes."""
        now = datetime.utcnow()
        window = timedelta(minutes=minutes)
        return [
            a for a in cls._anomalies
            if (now - a.timestamp) < window
        ]
