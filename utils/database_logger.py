# === Service de logging vers la base de données ===
# Capture les événements système et les stocke dans la table Log
# Permet d'afficher les logs importants dans l'interface admin

import asyncio
from datetime import datetime
from database import async_session
from models.log import Log


async def log_event(level: str, category: str, message: str, 
                   ip_address: str = None, user_id: str = None, 
                   details: str = None):
    """
    Logger un événement dans la base de données.
    À appeler manuellement depuis les routes/services.
    
    Args:
        level: info, warning, error, critical
        category: auth, analysis, payment, admin, security, system
        message: Le message principal du log
        ip_address: IP de l'utilisateur (optionnel)
        user_id: ID de l'utilisateur (optionnel)
        details: Détails supplémentaires (optionnel)
    """
    try:
        async with async_session() as session:
            log_entry = Log(
                level=level.lower(),
                category=category,
                message=message[:500],  # Limiter la taille
                details=details[:1000] if details else None,
                ip_address=ip_address,
                user_id=user_id,
                created_at=datetime.utcnow()
            )
            session.add(log_entry)
            await session.commit()
    except Exception as e:
        # Ne pas bloquer l'application si le logging échoue
        print(f"[LOG ERROR] Impossible d'écrire le log: {e}")


# Fonctions helper pour chaque catégorie
async def log_auth(message: str, ip: str = None, user_id: str = None, level: str = "info"):
    """Logger un événement d'authentification."""
    await log_event(level, "auth", message, ip, user_id)

async def log_analysis(message: str, ip: str = None, user_id: str = None, level: str = "info", details: str = None):
    """Logger un événement d'analyse."""
    await log_event(level, "analysis", message, ip, user_id, details)

async def log_payment(message: str, ip: str = None, user_id: str = None, level: str = "info"):
    """Logger un événement de paiement."""
    await log_event(level, "payment", message, ip, user_id)

async def log_admin(message: str, ip: str = None, user_id: str = None, level: str = "info"):
    """Logger un événement d'administration."""
    await log_event(level, "admin", message, ip, user_id)

async def log_security(message: str, ip: str = None, user_id: str = None, level: str = "warning"):
    """Logger un événement de sécurité."""
    await log_event(level, "security", message, ip, user_id)

async def log_system(message: str, level: str = "info"):
    """Logger un événement système."""
    await log_event(level, "system", message)


def setup_database_logging():
    """
    Fonction de compatibilité - le logging est maintenant manuel via les helpers.
    Les logs du terminal (print) ne sont PAS automatiquement capturés car
    cela cause des problèmes avec SQLAlchemy async.
    
    Pour logger un événement, utilisez les fonctions helper:
    - await log_auth("Connexion réussie", ip, user_id)
    - await log_analysis("Analyse image", ip, user_id, details="...")
    - await log_error("Erreur critique", details=traceback)
    """
    import logging
    logger = logging.getLogger('system')
    logger.info("[SYSTEM] Logger initialisé - Utilisez les fonctions log_*() pour capturer les événements")
    
    return None
