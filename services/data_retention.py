# === Service de Gestion de la Rétention des Données (RGPD) ===
# - Anonymisation automatique des anciennes analyses
# - Suppression des données après la durée de conservation légale
# - Consentement traçable

import asyncio
import json
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import UUID
from sqlalchemy import select, delete as sa_delete, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession


# --- Configuration de la rétention (en jours) ---
RETENTION_PERIODS = {
    "analysis_results": 365,      # Résultats d'analyse: 1 an
    "analysis_input_data": 90,    # Données soumises: 3 mois
    "user_activity_logs": 180,    # Logs d'activité: 6 mois
    "payment_history": 2555,      # Historique paiement: 7 ans (obligation légale)
    "user_consent": 3650,         # Consentements: 10 ans
    "deleted_accounts": 30,       # Données compte supprimé: 30 jours (puis anonymisé)
}


class DataRetentionService:
    """
    Service de gestion de la rétention des données conforme au RGPD.
    """
    
    @staticmethod
    async def anonymize_old_analyses(db: AsyncSession, days: int = None) -> int:
        """
        Anonymiser les analyses plus anciennes que le seuil.
        Conserve les métadonnées (score, verdict) mais supprime les données sensibles.
        
        Returns:
            Nombre d'analyses anonymisées
        """
        from models.analysis import Analysis
        
        threshold = days or RETENTION_PERIODS["analysis_results"]
        cutoff_date = datetime.utcnow() - timedelta(days=threshold)
        
        # Récupérer les analyses à anonymiser
        result = await db.execute(
            select(Analysis).where(
                Analysis.created_at < cutoff_date,
                Analysis.input_data.isnot(None)  # Pas déjà anonymisé
            )
        )
        analyses = result.scalars().all()
        
        count = 0
        for analysis in analyses:
            # Anonymiser les données sensibles
            analysis.input_data = "[ANONYMISÉ - Délai de conservation atteint]"
            analysis._input_data_encrypted = None
            analysis._result_encrypted = None
            analysis.summary = "[ANONYMISÉ]"
            analysis.pdf_report_url = None
            count += 1
        
        await db.flush()
        return count
    
    @staticmethod
    async def delete_old_logs(db: AsyncSession, days: int = None) -> int:
        """
        Supprimer les anciens logs système.
        
        Returns:
            Nombre de logs supprimés
        """
        from models.log import Log
        
        threshold = days or RETENTION_PERIODS["user_activity_logs"]
        cutoff_date = datetime.utcnow() - timedelta(days=threshold)
        
        result = await db.execute(
            sa_delete(Log).where(Log.created_at < cutoff_date)
        )
        await db.flush()
        return result.rowcount
    
    @staticmethod
    async def cleanup_deleted_accounts(db: AsyncSession, days: int = None) -> int:
        """
        Supprimer définitivement les données des comptes supprimés après la période de conservation.
        
        Returns:
            Nombre de comptes nettoyés
        """
        from models.user import User
        from models.subscription import Subscription
        from models.analysis import Analysis
        
        threshold = days or RETENTION_PERIODS["deleted_accounts"]
        cutoff_date = datetime.utcnow() - timedelta(days=threshold)
        
        # Trouver les utilisateurs marqués comme supprimés
        # Note: Nécessite d'ajouter un champ 'deleted_at' au modèle User
        # Pour l'instant, on suppose que les utilisateurs supprimés n'existent plus
        
        # Nettoyer les analyses orphelines (sans utilisateur associé)
        # et plus anciennes que le seuil
        result = await db.execute(
            sa_delete(Analysis).where(
                Analysis.created_at < cutoff_date,
                # Sous-requête pour trouver les analyses sans user
                Analysis.user_id.notin_(
                    select(User.id)
                )
            )
        )
        await db.flush()
        return result.rowcount
    
    @staticmethod
    async def generate_retention_report(db: AsyncSession) -> Dict[str, Any]:
        """
        Générer un rapport sur la politique de rétention.
        Utilisé pour l'audit RGPD.
        """
        from models.analysis import Analysis
        from models.log import Log
        from models.user import User
        
        now = datetime.utcnow()
        
        # Compter les analyses par âge
        analysis_ages = {
            "total": 0,
            "under_30_days": 0,
            "under_90_days": 0,
            "under_1_year": 0,
            "over_1_year": 0,
        }
        
        result = await db.execute(select(Analysis))
        analyses = result.scalars().all()
        
        for analysis in analyses:
            analysis_ages["total"] += 1
            age_days = (now - analysis.created_at).days
            
            if age_days < 30:
                analysis_ages["under_30_days"] += 1
            elif age_days < 90:
                analysis_ages["under_90_days"] += 1
            elif age_days < 365:
                analysis_ages["under_1_year"] += 1
            else:
                analysis_ages["over_1_year"] += 1
        
        # Compter les logs
        log_result = await db.execute(
            select(Log).where(Log.created_at > now - timedelta(days=180))
        )
        recent_logs = len(log_result.scalars().all())
        
        return {
            "generated_at": now.isoformat(),
            "retention_periods": RETENTION_PERIODS,
            "analysis_distribution": analysis_ages,
            "recent_logs_count": recent_logs,
            "total_users": await db.scalar(select(User).count()),
        }


class ConsentManager:
    """
    Gestionnaire de consentement utilisateur (RGPD).
    """
    
    CONSENT_TYPES = {
        "data_processing": "Traitement des données personnelles",
        "analytics": "Cookies analytiques",
        "marketing": "Communications marketing",
        "third_party": "Partage avec des tiers (APIs)",
    }
    
    @staticmethod
    async def record_consent(
        db: AsyncSession,
        user_id: UUID,
        consent_type: str,
        granted: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> None:
        """
        Enregistrer un consentement utilisateur.
        Obligatoire pour la conformité RGPD.
        """
        from models.log import Log
        
        # Créer un log traçable
        consent_log = Log(
            user_id=user_id,
            level="info",
            category="consent",
            message=f"Consentement {consent_type}: {'accordé' if granted else 'refusé'}",
            details=json.dumps({
                "consent_type": consent_type,
                "granted": granted,
                "ip_address": ip_address,
                "user_agent": user_agent[:200] if user_agent else None,
                "timestamp": datetime.utcnow().isoformat(),
            }),
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,
        )
        db.add(consent_log)
        await db.flush()
    
    @staticmethod
    async def get_user_consents(
        db: AsyncSession,
        user_id: UUID
    ) -> List[Dict[str, Any]]:
        """Récupérer l'historique des consentements d'un utilisateur."""
        from models.log import Log
        
        result = await db.execute(
            select(Log).where(
                Log.user_id == user_id,
                Log.category == "consent"
            ).order_by(Log.created_at.desc())
        )
        
        consents = []
        for log in result.scalars().all():
            try:
                details = json.loads(log.details) if log.details else {}
                consents.append({
                    "type": details.get("consent_type"),
                    "granted": details.get("granted"),
                    "timestamp": log.created_at.isoformat(),
                    "ip_address": details.get("ip_address"),
                })
            except json.JSONDecodeError:
                continue
        
        return consents
    
    @staticmethod
    async def revoke_all_consents(db: AsyncSession, user_id: UUID) -> None:
        """
        Révoquer tous les consentements (lors de la suppression de compte).
        """
        await ConsentManager.record_consent(
            db=db,
            user_id=user_id,
            consent_type="all",
            granted=False,
            ip_address=None,
            user_agent="System - Account deletion"
        )


# --- Tâche planifiée de nettoyage ---
async def run_data_retention_cleanup(db: AsyncSession) -> Dict[str, int]:
    """
    Exécuter le nettoyage complet des données selon la politique de rétention.
    À appeler via une tâche planifiée (cron ou Celery Beat).
    
    Usage:
        from database import async_session
        async with async_session() as db:
            results = await run_data_retention_cleanup(db)
    """
    service = DataRetentionService()
    
    results = {
        "analyses_anonymized": await service.anonymize_old_analyses(db),
        "logs_deleted": await service.delete_old_logs(db),
        "orphaned_cleaned": await service.cleanup_deleted_accounts(db),
    }
    
    # Logger le résultat
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"[Data Retention] Nettoyage terminé: {results}")
    
    return results
