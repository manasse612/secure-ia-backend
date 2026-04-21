# === Routes d'administration (Back-office) ===
# Réservées aux administrateurs Secure IA
# Toutes les routes commencent par /api/admin/

from fastapi import APIRouter, Depends, HTTPException, status, Query, Body, UploadFile, File, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel

from datetime import datetime, timedelta

from database import get_db
from models.user import User
from models.analysis import Analysis
from models.subscription import Subscription
from models.log import Log
from models.notification import Notification
from models.invoice import Invoice
from schemas.user import UserResponse
from utils.security import get_admin_user

# Créer le routeur avec le préfixe /api/admin
router = APIRouter(prefix="/api/admin", tags=["Administration"])


# --- Schémas pour les requêtes admin ---
class QuotaUpdate(BaseModel):
    max_analyses_per_month: str

class NotificationCreate(BaseModel):
    user_id: Optional[str] = None
    title: str
    message: str
    type: str = "info"

class UserRoleUpdate(BaseModel):
    role: str


async def _log_admin_action(
    db: AsyncSession,
    admin,
    message: str,
    category: str = "admin",
    level: str = "info",
    details: str = None,
    endpoint: str = None,
    request: Request = None,
):
    """Helper : enregistre une action admin dans les logs."""
    log_entry = Log(
        user_id=admin.id,
        level=level,
        category=category,
        message=message,
        details=details,
        endpoint=endpoint,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent", "")[:500] if request else None,
    )
    db.add(log_entry)


@router.get("/dashboard")
async def get_dashboard(
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Récupérer les KPIs du tableau de bord administrateur.
    - Nombre total d'utilisateurs
    - Nombre d'analyses effectuées
    - Répartition par rôle
    - Analyses du jour
    - Revenus réels (basés sur subscriptions actives)
    """
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Compter les utilisateurs
    total_users = await db.execute(select(func.count()).select_from(User))
    active_users = await db.execute(
        select(func.count()).select_from(User).where(User.is_active == True)
    )

    # Compter les analyses
    total_analyses = await db.execute(select(func.count()).select_from(Analysis))
    today_analyses = await db.execute(
        select(func.count()).select_from(Analysis).where(Analysis.created_at >= today)
    )

    # Répartition par rôle (directement en strings)
    roles = ['free', 'pro', 'business', 'admin']
    role_counts = {}
    for role in roles:
        count_result = await db.execute(
            select(func.count()).select_from(User).where(User.role == role)
        )
        role_counts[role] = count_result.scalar() or 0

    # Récupérer les prix depuis la configuration du site
    from services.config_helper import get_config_value
    
    price_pro = float(await get_config_value("price_pro", db) or "29.90")
    price_business = float(await get_config_value("price_business", db) or "99.90")
    
    # Calculer les revenus mensuels réels (basés sur subscriptions actives)
    subs_result = await db.execute(
        select(Subscription).where(Subscription.status == 'active')
    )
    active_subs = subs_result.scalars().all()
    
    PRICING = {
        'pro': price_pro,
        'business': price_business,
        'enterprise': 0  # Sur devis
    }
    
    total_revenue = 0
    revenue_by_plan = {}
    
    for sub in active_subs:
        if sub.plan in PRICING:
            amount = PRICING[sub.plan]
            total_revenue += amount
            revenue_by_plan[sub.plan] = revenue_by_plan.get(sub.plan, 0) + amount

    return {
        "users": {
            "total": total_users.scalar() or 0,
            "active": active_users.scalar() or 0,
            "by_role": role_counts,
        },
        "analyses": {
            "total": total_analyses.scalar() or 0,
            "today": today_analyses.scalar() or 0,
        },
        "revenue": {
            "total": round(total_revenue, 2),
            "by_plan": revenue_by_plan,
            "currency": "EUR"
        }
    }


@router.get("/activity")
async def get_activity_stats(
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Statistiques d'activité pour le dashboard admin :
    - Analyses par jour (7 derniers jours)
    - Répartition par type d'analyse
    - 10 dernières analyses
    - Utilisation estimée des APIs (Hive AI, OpenAI, VirusTotal)
    """
    now = datetime.utcnow()
    seven_days_ago = now - timedelta(days=7)

    # --- Analyses par jour (7 derniers jours) ---
    daily = []
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count_res = await db.execute(
            select(func.count()).select_from(Analysis)
            .where(Analysis.created_at >= day_start, Analysis.created_at < day_end)
        )
        daily.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "label": day_start.strftime("%a %d/%m"),
            "count": count_res.scalar() or 0,
        })

    # --- Répartition par type ---
    type_counts = {}
    for atype in ["image", "text", "url", "video"]:
        res = await db.execute(
            select(func.count()).select_from(Analysis)
            .where(Analysis.analysis_type == atype)
        )
        type_counts[atype] = res.scalar() or 0

    # --- 10 dernières analyses ---
    recent_res = await db.execute(
        select(Analysis)
        .order_by(Analysis.created_at.desc())
        .limit(10)
    )
    recent_analyses = recent_res.scalars().all()
    recent = [
        {
            "id": str(a.id),
            "type": a.analysis_type,
            "score": a.score,
            "verdict": a.verdict,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "processing_time_ms": a.processing_time_ms,
        }
        for a in recent_analyses
    ]

    # --- Utilisation estimée des APIs ---
    total_analyses_res = await db.execute(select(func.count()).select_from(Analysis))
    total_analyses = total_analyses_res.scalar() or 0

    image_count = type_counts.get("image", 0)
    video_count = type_counts.get("video", 0)
    text_count = type_counts.get("text", 0)
    url_count = type_counts.get("url", 0)

    # Estimations de coûts par appel (approximatifs)
    hive_cost_per_call = 0.005   # ~$0.005 par image/vidéo
    openai_cost_per_call = 0.003  # ~$0.003 par analyse texte
    virustotal_cost_per_call = 0.0  # Gratuit (API publique)

    api_usage = {
        "hive_ai": {
            "calls": image_count + video_count,
            "estimated_cost": round((image_count + video_count) * hive_cost_per_call, 2),
            "description": "Détection IA images & vidéos",
        },
        "openai": {
            "calls": text_count,
            "estimated_cost": round(text_count * openai_cost_per_call, 2),
            "description": "Fact-checking & analyse texte",
        },
        "virustotal": {
            "calls": url_count,
            "estimated_cost": 0.00,
            "description": "Analyse sécurité URLs",
        },
    }

    total_api_cost = sum(v["estimated_cost"] for v in api_usage.values())

    return {
        "daily": daily,
        "by_type": type_counts,
        "recent": recent,
        "api_usage": api_usage,
        "total_api_cost": round(total_api_cost, 2),
    }


@router.get("/users")
async def list_users(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    search: str = Query(default=None),
    role: str = Query(default=None),
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Lister tous les utilisateurs avec pagination et filtres.
    - Recherche par email ou nom
    - Filtrage par rôle (string)
    """
    query = select(User)

    # Filtrer par recherche
    if search:
        query = query.where(
            (User.email.ilike(f"%{search}%")) | 
            (User.full_name.ilike(f"%{search}%"))
        )

    # Filtrer par rôle (comparaison directe string)
    if role:
        query = query.where(User.role == role)

    # Compter le total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Pagination
    query = query.order_by(User.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    users = result.scalars().all()

    return {
        "users": [UserResponse.model_validate(u) for u in users],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }


@router.put("/users/{user_id}/role")
async def update_user_role(
    user_id: UUID,
    data: UserRoleUpdate,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Modifier le rôle d'un utilisateur (string direct).
    Met à jour automatiquement l'abonnement avec le quota correspondant.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    # Vérifier que le rôle est valide
    valid_roles = ['free', 'pro', 'business', 'admin']
    if data.role not in valid_roles:
        raise HTTPException(
            status_code=400, 
            detail=f"Rôle invalide. Doit être l'un de : {', '.join(valid_roles)}"
        )

    old_role = user.role
    # Mise à jour directe avec string
    user.role = data.role
    
    # --- MISE À JOUR AUTOMATIQUE DE L'ABONNEMENT ---
    from services.config_helper import get_config_value
    
    # Récupérer le quota correspondant au nouveau rôle
    quota_map = {
        "free": "quota_free",
        "pro": "quota_pro",
        "business": "quota_business",
        "admin": "quota_free"  # Les admins utilisent le quota free par défaut
    }
    
    if data.role in quota_map:
        quota_key = quota_map[data.role]
        quota_value = await get_config_value(quota_key, db)
        
        # Chercher l'abonnement existant
        sub_result = await db.execute(
            select(Subscription).where(Subscription.user_id == user_id)
        )
        subscription = sub_result.scalar_one_or_none()
        
        # Déterminer le nom du plan pour l'abonnement
        plan_name = data.role
        
        if subscription:
            # Mettre à jour l'abonnement existant (CONVERSION EN STRING)
            subscription.plan = plan_name
            subscription.max_analyses_per_month = str(int(quota_value))  # ← CORRECTION
            subscription.status = "active"
        else:
            # Créer un nouvel abonnement si inexistant (CONVERSION EN STRING)
            new_sub = Subscription(
                user_id=user_id,
                plan=plan_name,
                status="active",
                price_monthly=0.0,
                max_analyses_per_month=str(int(quota_value)),  # ← CORRECTION
                current_analysis_count="0",
            )
            db.add(new_sub)
    
    await _log_admin_action(
        db, admin, 
        f"Rôle de {user.email} modifié : {old_role} → {data.role} (abonnement mis à jour)", 
        endpoint="PUT /admin/users/{id}/role", 
        details=f"user_id={user_id}", 
        request=request
    )
    await db.flush()

    return {
        "message": f"Rôle mis à jour : {data.role} (abonnement synchronisé)",
        "user_id": str(user_id),
        "role": data.role
    }


@router.put("/users/{user_id}/suspend")
async def suspend_user(
    user_id: UUID,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Suspendre ou réactiver un compte utilisateur.
    Inverse l'état actif/inactif du compte.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    # Empêcher de suspendre un autre admin (sauf si c'est un super-admin plus tard)
    if user.role == 'admin' and admin.id != user_id:
        raise HTTPException(status_code=403, detail="Impossible de suspendre un autre administrateur")

    # Inverser le statut
    user.is_active = not user.is_active
    status_text = "activé" if user.is_active else "suspendu"
    await _log_admin_action(db, admin, f"Compte {user.email} {status_text}", endpoint="PUT /admin/users/{id}/suspend", details=f"user_id={user_id}, is_active={user.is_active}", request=request, level="warning" if not user.is_active else "info")
    await db.flush()

    return {
        "message": f"Compte {status_text}",
        "user_id": str(user_id),
        "is_active": user.is_active
    }


@router.get("/logs")
async def get_logs(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    level: str = Query(default=None),
    category: str = Query(default=None),
    search: str = Query(default=None),
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Consulter les logs système.
    Filtrage par niveau (info, warning, error, critical), catégorie et recherche textuelle.
    """
    query = select(Log)

    # Filtres directs (strings)
    if level:
        query = query.where(Log.level == level)
    if category:
        query = query.where(Log.category == category)
    
    # Recherche textuelle dans le message
    if search:
        query = query.where(Log.message.ilike(f"%{search}%"))

    # Compter le total avant pagination
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Pagination
    query = query.order_by(Log.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    logs = result.scalars().all()

    return {
        "logs": [
            {
                "id": str(log.id),
                "level": log.level,
                "category": log.category,
                "message": log.message,
                "details": log.details,
                "ip_address": log.ip_address,
                "user_id": str(log.user_id) if log.user_id else None,
                "created_at": log.created_at.isoformat() if log.created_at else None,
            }
            for log in logs
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }


# ============================================================
# Routes de gestion des quotas
# ============================================================

@router.get("/users/{user_id}/quota")
async def get_user_quota(
    user_id: UUID,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Récupérer le quota d'analyses d'un utilisateur spécifique.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    # Récupérer l'abonnement
    sub_result = await db.execute(select(Subscription).where(Subscription.user_id == user_id))
    subscription = sub_result.scalar_one_or_none()

    return {
        "user_id": str(user_id),
        "email": user.email,
        "role": user.role,
        "monthly_analysis_count": user.monthly_analysis_count or "0",
        "subscription": {
            "plan": subscription.plan if subscription else "free",
            "max_analyses_per_month": subscription.max_analyses_per_month if subscription else "10",
            "current_analysis_count": subscription.current_analysis_count if subscription else "0",
            "status": subscription.status if subscription else "inactive",
            "start_date": subscription.start_date.isoformat() if subscription and subscription.start_date else None,
            "end_date": subscription.end_date.isoformat() if subscription and subscription.end_date else None,
        } if subscription else None,
    }


@router.put("/users/{user_id}/quota")
async def update_user_quota(
    user_id: UUID,
    data: QuotaUpdate,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Modifier le quota d'analyses d'un utilisateur.
    Permet à l'admin de personnaliser les limites.
    """
    # Récupérer l'abonnement
    sub_result = await db.execute(select(Subscription).where(Subscription.user_id == user_id))
    subscription = sub_result.scalar_one_or_none()

    if not subscription:
        raise HTTPException(status_code=404, detail="Abonnement non trouvé pour cet utilisateur")

    old_quota = subscription.max_analyses_per_month
    subscription.max_analyses_per_month = data.max_analyses_per_month
    await _log_admin_action(db, admin, f"Quota utilisateur modifié : {old_quota} → {data.max_analyses_per_month}", endpoint="PUT /admin/users/{id}/quota", details=f"user_id={user_id}", request=request)
    await db.flush()

    return {
        "message": f"Quota mis à jour : {data.max_analyses_per_month} analyses/mois",
        "user_id": str(user_id),
        "max_analyses_per_month": data.max_analyses_per_month
    }


@router.put("/users/{user_id}/reset-quota")
async def reset_user_quota(
    user_id: UUID,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Réinitialiser le compteur d'analyses d'un utilisateur.
    Remet le compteur mensuel à zéro.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

    user.monthly_analysis_count = "0"

    # Aussi réinitialiser le compteur dans la subscription
    sub_result = await db.execute(select(Subscription).where(Subscription.user_id == user_id))
    subscription = sub_result.scalar_one_or_none()
    if subscription:
        subscription.current_analysis_count = "0"

    await _log_admin_action(db, admin, f"Compteur d'analyses réinitialisé pour {user.email}", endpoint="PUT /admin/users/{id}/reset-quota", details=f"user_id={user_id}", request=request)
    await db.flush()

    return {
        "message": "Compteur d'analyses réinitialisé",
        "user_id": str(user_id),
        "monthly_analysis_count": "0"
    }


# ============================================================
# Routes de gestion des abonnements
# ============================================================

@router.get("/subscriptions")
async def list_subscriptions(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    status: str = Query(default=None),
    plan: str = Query(default=None),
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Lister tous les abonnements avec pagination.
    Permet de voir l'état des abonnements actifs, expirés, annulés.
    """
    query = select(Subscription)

    if status:
        query = query.where(Subscription.status == status)
    if plan:
        query = query.where(Subscription.plan == plan)

    # Compter le total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Pagination
    query = query.order_by(Subscription.created_at.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    subscriptions = result.scalars().all()

    # Récupérer les infos utilisateur pour chaque abonnement
    subscriptions_data = []
    for sub in subscriptions:
        user_result = await db.execute(select(User).where(User.id == sub.user_id))
        user = user_result.scalar_one_or_none()
        
        subscriptions_data.append({
            "id": str(sub.id),
            "user_id": str(sub.user_id),
            "user_email": user.email if user else None,
            "user_name": user.full_name if user else None,
            "plan": sub.plan,
            "status": sub.status,
            "max_analyses_per_month": sub.max_analyses_per_month,
            "current_analysis_count": sub.current_analysis_count,
            "start_date": sub.start_date.isoformat() if sub.start_date else None,
            "end_date": sub.end_date.isoformat() if sub.end_date else None,
            "cancelled_at": sub.cancelled_at.isoformat() if sub.cancelled_at else None,
            "stripe_subscription_id": sub.stripe_subscription_id,
        })

    return {
        "subscriptions": subscriptions_data,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }


@router.put("/subscriptions/{subscription_id}/cancel")
async def cancel_subscription(
    subscription_id: UUID,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Annuler un abonnement (remboursement ou arrêt).
    """
    result = await db.execute(select(Subscription).where(Subscription.id == subscription_id))
    subscription = result.scalar_one_or_none()

    if not subscription:
        raise HTTPException(status_code=404, detail="Abonnement non trouvé")

    subscription.status = "cancelled"
    subscription.cancelled_at = datetime.utcnow()
    await _log_admin_action(db, admin, f"Abonnement {subscription.plan} annulé (user_id={subscription.user_id})", endpoint="PUT /admin/subscriptions/{id}/cancel", details=f"subscription_id={subscription_id}, plan={subscription.plan}", request=request, category="payment", level="warning")
    await db.flush()

    return {
        "message": "Abonnement annulé",
        "subscription_id": str(subscription_id),
        "status": "cancelled"
    }


# ============================================================
# Routes de notifications
# ============================================================

@router.post("/notifications")
async def send_notification(
    data: NotificationCreate,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Envoyer une notification à un utilisateur ou à tous.
    - user_id = null → notification globale (tous les utilisateurs)
    - user_id = UUID → notification ciblée
    """
    user_uuid = None
    if data.user_id:
        try:
            user_uuid = UUID(data.user_id)
            # Vérifier que l'utilisateur existe
            result = await db.execute(select(User).where(User.id == user_uuid))
            if not result.scalar_one_or_none():
                raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        except ValueError:
            raise HTTPException(status_code=400, detail="ID utilisateur invalide")

    notification = Notification(
        user_id=user_uuid,
        title=data.title,
        message=data.message,
        type=data.type,
    )
    db.add(notification)
    target_label = f"utilisateur {data.user_id}" if data.user_id else "tous les utilisateurs"
    await _log_admin_action(db, admin, f"Notification envoyée à {target_label} : {data.title}", endpoint="POST /admin/notifications", details=f"type={data.type}, target={data.user_id or 'all'}", request=request)
    await db.flush()

    return {
        "message": "Notification envoyée",
        "id": str(notification.id),
        "target": data.user_id or "all",
    }


@router.get("/notifications")
async def list_notifications(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Lister toutes les notifications envoyées par l'admin.
    """
    query = select(Notification).order_by(Notification.created_at.desc())
    
    # Compter le total
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0
    
    # Pagination
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await db.execute(query)
    notifications = result.scalars().all()

    return {
        "notifications": [
            {
                "id": str(n.id),
                "user_id": str(n.user_id) if n.user_id else None,
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "is_read": n.is_read,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in notifications
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }


# ============================================================
# Routes de configuration du site
# ============================================================

@router.get("/config")
async def get_site_config(
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Récupérer toute la configuration du site."""
    from models.site_config import SiteConfig
    result = await db.execute(select(SiteConfig).order_by(SiteConfig.key))
    configs = result.scalars().all()

    return {
        "config": {
            c.key: {
                "value": c.value,
                "description": c.description,
                "updated_at": c.updated_at.isoformat() if c.updated_at else None,
            }
            for c in configs
        }
    }


@router.put("/config/{key}")
async def update_site_config(
    key: str,
    value: str = Body(..., embed=True),
    request: Request = None,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Modifier une valeur de configuration."""
    from models.site_config import SiteConfig
    result = await db.execute(select(SiteConfig).where(SiteConfig.key == key))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail=f"Clé '{key}' non trouvée")

    old_value = config.value
    config.value = value
    config.updated_at = datetime.utcnow()
    await _log_admin_action(db, admin, f"Configuration '{key}' modifiée : {old_value} → {value}", endpoint=f"PUT /admin/config/{key}", details=f"key={key}", request=request)
    await db.flush()

    return {"message": f"Configuration '{key}' mise à jour", "key": key, "value": value}


# ============================================================
# Routes de gestion des offres
# ============================================================

@router.get("/offers")
async def list_offers(
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Lister toutes les offres."""
    from models.offer import Offer
    result = await db.execute(select(Offer).order_by(Offer.created_at.desc()))
    offers = result.scalars().all()

    return {
        "offers": [
            {
                "id": str(o.id),
                "title": o.title,
                "description": o.description,
                "badge_text": o.badge_text,
                "badge_color": o.badge_color,
                "image_url": o.image_url,
                "cta_text": o.cta_text,
                "cta_link": o.cta_link,
                "is_active": o.is_active,
                "start_date": o.start_date.isoformat() if o.start_date else None,
                "end_date": o.end_date.isoformat() if o.end_date else None,
                "created_at": o.created_at.isoformat() if o.created_at else None,
            }
            for o in offers
        ]
    }


@router.post("/offers")
async def create_offer(
    title: str = Body(...),
    description: str = Body(...),
    badge_text: str = Body(default=None),
    badge_color: str = Body(default="primary"),
    image_url: str = Body(default=None),
    cta_text: str = Body(default=None),
    cta_link: str = Body(default=None),
    is_active: bool = Body(default=True),
    start_date: str = Body(default=None),
    end_date: str = Body(default=None),
    request: Request = None,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Créer une nouvelle offre/annonce."""
    from models.offer import Offer

    offer = Offer(
        title=title,
        description=description,
        badge_text=badge_text,
        badge_color=badge_color,
        image_url=image_url,
        cta_text=cta_text,
        cta_link=cta_link,
        is_active=is_active,
        start_date=datetime.fromisoformat(start_date) if start_date else None,
        end_date=datetime.fromisoformat(end_date) if end_date else None,
    )
    db.add(offer)
    await _log_admin_action(db, admin, f"Offre créée : {title}", endpoint="POST /admin/offers", details=f"is_active={is_active}", request=request)
    await db.flush()

    return {"message": "Offre créée", "id": str(offer.id), "title": title}


@router.put("/offers/{offer_id}")
async def update_offer(
    offer_id: UUID,
    title: str = Body(default=None),
    description: str = Body(default=None),
    badge_text: str = Body(default=None),
    badge_color: str = Body(default=None),
    image_url: str = Body(default=None),
    cta_text: str = Body(default=None),
    cta_link: str = Body(default=None),
    is_active: bool = Body(default=None),
    start_date: str = Body(default=None),
    end_date: str = Body(default=None),
    request: Request = None,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Modifier une offre existante."""
    from models.offer import Offer
    result = await db.execute(select(Offer).where(Offer.id == offer_id))
    offer = result.scalar_one_or_none()
    if not offer:
        raise HTTPException(status_code=404, detail="Offre non trouvée")

    if title is not None: offer.title = title
    if description is not None: offer.description = description
    if badge_text is not None: offer.badge_text = badge_text
    if badge_color is not None: offer.badge_color = badge_color
    if image_url is not None: offer.image_url = image_url
    if cta_text is not None: offer.cta_text = cta_text
    if cta_link is not None: offer.cta_link = cta_link
    if is_active is not None: offer.is_active = is_active
    if start_date is not None: offer.start_date = datetime.fromisoformat(start_date)
    if end_date is not None: offer.end_date = datetime.fromisoformat(end_date)
    offer.updated_at = datetime.utcnow()
    await _log_admin_action(db, admin, f"Offre modifiée : {offer.title}", endpoint="PUT /admin/offers/{id}", details=f"offer_id={offer_id}", request=request)
    await db.flush()

    return {"message": "Offre mise à jour", "id": str(offer_id)}


@router.delete("/offers/{offer_id}")
async def delete_offer(
    offer_id: UUID,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Supprimer une offre."""
    from models.offer import Offer
    result = await db.execute(select(Offer).where(Offer.id == offer_id))
    offer = result.scalar_one_or_none()
    if not offer:
        raise HTTPException(status_code=404, detail="Offre non trouvée")

    offer_title = offer.title
    await db.delete(offer)
    await _log_admin_action(db, admin, f"Offre supprimée : {offer_title}", endpoint="DELETE /admin/offers/{id}", details=f"offer_id={offer_id}", request=request, level="warning")
    await db.flush()
    return {"message": "Offre supprimée", "id": str(offer_id)}


# ============================================================
# Suppression d'utilisateur
# ============================================================

@router.delete("/users/{user_id}")
async def delete_user(
    user_id: UUID,
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """Supprimer définitivement un utilisateur et toutes ses données."""
    from sqlalchemy import delete as sa_delete

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
    if user.role == 'admin' and admin.id != user_id:
        raise HTTPException(status_code=403, detail="Impossible de supprimer un autre administrateur")

    email = user.email

    # Supprimer toutes les données liées avant de supprimer l'utilisateur
    await db.execute(sa_delete(Subscription).where(Subscription.user_id == user_id))
    await db.execute(sa_delete(Analysis).where(Analysis.user_id == user_id))
    await db.execute(sa_delete(Invoice).where(Invoice.user_id == user_id))
    await db.execute(sa_delete(Log).where(Log.user_id == user_id))
    await db.execute(sa_delete(Notification).where(Notification.user_id == user_id))

    await db.delete(user)
    await _log_admin_action(db, admin, f"Utilisateur supprimé : {email}", endpoint="DELETE /admin/users/{id}", details=f"user_id={user_id}", request=request, level="critical")
    await db.flush()
    return {"message": f"Utilisateur {email} supprimé", "user_id": str(user_id)}


# ============================================================
# Upload d'images (offres, etc.)
# ============================================================

@router.post("/upload")
async def upload_image(
    file: UploadFile = File(...),
    request: Request = None,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload une image et retourne son URL publique.
    Stocke le fichier dans backend/static/uploads/.
    """
    import os
    import uuid as uuid_mod

    # Vérifier le type de fichier
    allowed_types = ["image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Type de fichier non autorisé: {file.content_type}. Formats acceptés: JPG, PNG, GIF, WebP, SVG.",
        )

    # Limiter la taille (5 Mo)
    contents = await file.read()
    if len(contents) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fichier trop volumineux (max 5 Mo).",
        )

    # Créer le dossier uploads s'il n'existe pas
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # Générer un nom unique
    ext = os.path.splitext(file.filename or "image.jpg")[1] or ".jpg"
    filename = f"{uuid_mod.uuid4().hex}{ext}"
    filepath = os.path.join(upload_dir, filename)

    # Sauvegarder le fichier
    with open(filepath, "wb") as f:
        f.write(contents)

    # Retourner l'URL publique
    url = f"/static/uploads/{filename}"
    await _log_admin_action(db, admin, f"Image uploadée : {file.filename} ({len(contents)} octets)", endpoint="POST /admin/upload", details=f"filename={filename}, size={len(contents)}", request=request)
    await db.flush()
    return {"url": url, "filename": filename, "size": len(contents)}


# ============================================================
# Gestion de la rétention des données (RGPD)
# ============================================================

@router.get("/data-retention/report")
async def get_data_retention_report(
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Générer un rapport sur la politique de rétention des données.
    Conformité RGPD - montre la distribution des données par âge.
    """
    from services.data_retention import DataRetentionService
    
    report = await DataRetentionService.generate_retention_report(db)
    return report


@router.post("/data-retention/cleanup")
async def run_data_retention_cleanup(
    request: Request,
    admin=Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Exécuter manuellement le nettoyage des données selon la politique de rétention.
    Anonymise les vieilles analyses et supprime les logs expirés.
    """
    from services.data_retention import run_data_retention_cleanup
    
    results = await run_data_retention_cleanup(db)
    
    await _log_admin_action(
        db, admin,
        f"Nettoyage RGPD exécuté: {results}",
        endpoint="POST /admin/data-retention/cleanup",
        level="warning",
        request=request
    )
    await db.flush()
    
    return {
        "message": "Nettoyage des données terminé",
        "results": results,
        "retention_periods": {
            "analysis_results": "1 an (puis anonymisation)",
            "activity_logs": "6 mois",
            "payment_history": "7 ans (obligation légale)",
        }
    }


# ============================================================
# Monitoring des anomalies et sécurité
# ============================================================

@router.get("/security/anomalies")
async def get_recent_anomalies(
    minutes: int = 60,
    admin=Depends(get_admin_user),
):
    """
    Récupérer les anomalies de sécurité détectées récemment.
    Détecte les attaques brute force, DDoS, et comportements suspects.
    """
    from services.anomaly_detection import AnomalyDetector
    
    anomalies = AnomalyDetector.get_recent_anomalies(minutes=minutes)
    
    return {
        "anomalies": [
            {
                "type": a.type.value,
                "severity": a.severity,
                "user_id": a.user_id,
                "ip_address": a.ip_address,
                "description": a.description,
                "details": a.details,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in anomalies
        ],
        "count": len(anomalies),
        "time_window_minutes": minutes,
    }


@router.get("/security/rate-limits")
async def get_rate_limit_status(
    admin=Depends(get_admin_user),
):
    """
    Récupérer le statut actuel des rate limits (monitoring).
    """
    from utils.rate_limiter_advanced import AdvancedRateLimiter
    
    return {
        "default_limits": AdvancedRateLimiter.THRESHOLDS,
        "message": "Les rate limits sont actifs et protègent l'API",
        "protection_endpoints": [
            "/api/analysis/image",
            "/api/analysis/video",
            "/api/analysis/text",
            "/api/analysis/url",
        ]
    }


@router.post("/security/test-anomaly-detection")
async def test_anomaly_detection(
    request: Request,
    anomaly_type: str = Body(...),
    admin=Depends(get_admin_user),
):
    """
    Tester le système de détection d'anomalies (DEBUG uniquement).
    """
    from config import settings
    
    if not settings.debug:
        raise HTTPException(
            status_code=403,
            detail="Cet endpoint est uniquement disponible en mode debug"
        )
    
    from services.anomaly_detection import AnomalyDetector, AnomalyEvent, AnomalyType
    
    # Créer un faux événement d'anomalie
    test_event = AnomalyEvent(
        type=AnomalyType(anomaly_type) if anomaly_type in [t.value for t in AnomalyType] else AnomalyType.UNUSUAL_ANALYSIS_PATTERN,
        severity="medium",
        user_id=str(admin.id),
        ip_address=request.client.host if request.client else None,
        description="Test de détection d'anomalie",
        details={"test": True, "admin": admin.email},
        timestamp=datetime.utcnow()
    )
    
    await AnomalyDetector.report_anomaly(test_event)
    
    return {"message": "Test d'anomalie envoyé", "anomaly": test_event}