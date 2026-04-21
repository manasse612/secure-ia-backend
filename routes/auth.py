# === Routes d'authentification ===
# Gère l'inscription, la connexion, le profil et le rafraîchissement des tokens
# Toutes les routes commencent par /api/auth/

from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime

from database import get_db
from config import settings
from models.user import User
from schemas.user import UserCreate, UserLogin, UserResponse, TokenResponse, UserUpdate, PasswordChange
from services.auth_service import register_user, login_user, refresh_tokens
from utils.security import get_current_user, decode_token, verify_password, hash_password, create_access_token, create_refresh_token
from utils.database_logger import log_auth
from fastapi import Request

# Créer le routeur avec le préfixe /api/auth
router = APIRouter(prefix="/api/auth", tags=["Authentification"])


@router.post("/register", status_code=201)
async def register(
    user_data: UserCreate, 
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Inscrire un nouvel utilisateur.
    - Crée le compte avec email + mot de passe
    - Crée un abonnement gratuit par défaut
    - Envoie un code de vérification par email
    - L'utilisateur doit vérifier son email avant de se connecter
    """
    result = await register_user(db, user_data)
    
    # Logger l'inscription
    await log_auth(
        f"Nouvel utilisateur inscrit: {user_data.email}",
        ip=request.client.host,
        level="info"
    )
    
    return result


@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: UserLogin, 
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Connecter un utilisateur existant.
    - Vérifie l'email et le mot de passe
    - Retourne les tokens JWT
    """
    result = await login_user(db, login_data)
    
    # Logger la connexion
    await log_auth(
        f"Connexion réussie: {login_data.email}",
        ip=request.client.host,
        user_id=str(result.user.id),
        level="info"
    )
    
    return result


@router.get("/me", response_model=UserResponse)
async def get_profile(current_user=Depends(get_current_user)):
    """
    Récupérer le profil de l'utilisateur connecté.
    Nécessite un token JWT valide dans le header Authorization.
    """
    return UserResponse.model_validate(current_user)


@router.put("/me", response_model=UserResponse)
async def update_profile(
    update_data: UserUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Mettre à jour le profil de l'utilisateur connecté.
    Seuls les champs fournis sont modifiés.
    """
    # Mettre à jour uniquement les champs non-nuls
    if update_data.full_name is not None:
        current_user.full_name = update_data.full_name
    if update_data.language is not None:
        current_user.language = update_data.language
    if update_data.avatar_url is not None:
        current_user.avatar_url = update_data.avatar_url

    await db.flush()
    return UserResponse.model_validate(current_user)


@router.post("/refresh")
async def refresh(refresh_token: str, db: AsyncSession = Depends(get_db)):
    """
    Rafraîchir les tokens JWT.
    Appelé automatiquement quand le token d'accès expire.
    Nécessite un refresh_token valide.
    """
    # Décoder le refresh token
    payload = decode_token(refresh_token)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de rafraîchissement invalide",
        )

    user_id = payload.get("sub")
    return await refresh_tokens(db, user_id)


@router.get("/google")
async def google_login(redirect: str = "/dashboard"):
    """
    Rediriger vers Google pour l'authentification OAuth.
    Le paramètre redirect indique où renvoyer l'utilisateur après connexion.
    """
    from urllib.parse import urlencode
    if not settings.google_client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OAuth non configuré (GOOGLE_CLIENT_ID manquant)",
        )
    params = urlencode({
        "client_id": settings.google_client_id,
        "redirect_uri": f"{settings.backend_url}/api/auth/google/callback",
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": redirect,
    })
    from fastapi.responses import RedirectResponse
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{params}")


@router.get("/google/callback")
async def google_callback(
    code: str = None,
    state: str = "/dashboard",
    error: str = None,
    platform: str = None,  # 'mobile' pour app Capacitor
    db: AsyncSession = Depends(get_db),
):
    """
    Callback Google OAuth. Échange le code contre un token,
    récupère le profil, crée ou connecte l'utilisateur.
    
    Pour l'app mobile (platform=mobile), retourne JSON au lieu de redirect.
    """
    from fastapi.responses import RedirectResponse, JSONResponse
    import httpx

    if error or not code:
        if platform == 'mobile':
            return JSONResponse({"error": "google_denied", "detail": "Authentification refusée"}, status_code=400)
        return RedirectResponse(f"{settings.app_url}/login?error=google_denied")

    if not settings.google_client_id or not settings.google_client_secret:
        if platform == 'mobile':
            return JSONResponse({"error": "google_not_configured"}, status_code=400)
        return RedirectResponse(f"{settings.app_url}/login?error=google_not_configured")

    # Échanger le code contre un token
    async with httpx.AsyncClient() as client:
        token_res = await client.post("https://oauth2.googleapis.com/token", data={
            "code": code,
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "redirect_uri": f"{settings.backend_url}/api/auth/google/callback",
            "grant_type": "authorization_code",
        })
        if token_res.status_code != 200:
            return RedirectResponse(f"{settings.app_url}/login?error=google_token_failed")
        token_data = token_res.json()

        # Récupérer le profil Google
        userinfo_res = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {token_data['access_token']}"},
        )
        if userinfo_res.status_code != 200:
            return RedirectResponse(f"{settings.app_url}/login?error=google_profile_failed")
        google_user = userinfo_res.json()

    google_email = google_user.get("email")
    google_name = google_user.get("name", "")
    google_id = google_user.get("id")
    google_avatar = google_user.get("picture")

    if not google_email:
        return RedirectResponse(f"{settings.app_url}/login?error=google_no_email")

    # Chercher l'utilisateur existant
    result = await db.execute(select(User).where(User.email == google_email))
    user = result.scalar_one_or_none()

    import uuid as uuid_mod
    from services.config_helper import get_config_value

    if not user:
        # Créer un nouvel utilisateur via Google
        from models.subscription import Subscription
        # Récupérer le quota gratuit depuis la config (cohérent avec auth local)
        quota_free = await get_config_value("quota_free", db)
        session_token = str(uuid_mod.uuid4())
        user = User(
            email=google_email,
            full_name=google_name,
            hashed_password=None,
            role="free",
            auth_provider="google",
            google_id=google_id,
            avatar_url=google_avatar,
            language="fr",
            is_active=True,
            is_verified=True,
            monthly_analysis_count="0",
            active_session_token=session_token,
        )
        db.add(user)
        await db.flush()

        subscription = Subscription(
            user_id=user.id,
            plan="free",
            status="active",
            price_monthly=0.0,
            max_analyses_per_month=str(int(quota_free)),  # ← CORRIGÉ : utilise quota_free
            current_analysis_count="0",
        )
        db.add(subscription)
        await db.flush()
    else:
        # Mettre à jour les infos Google
        if not user.google_id:
            user.google_id = google_id
        if google_avatar and not user.avatar_url:
            user.avatar_url = google_avatar
        if not user.is_active:
            return RedirectResponse(f"{settings.app_url}/login?error=account_disabled")
        # Vérifier session unique
        if user.active_session_token:
            return RedirectResponse(f"{settings.app_url}/login?error=already_connected")
        session_token = str(uuid_mod.uuid4())
        user.active_session_token = session_token
        user.last_login = datetime.utcnow()
        await db.flush()

    # Générer les tokens JWT avec session_token
    access_token = create_access_token(str(user.id), user.role, user.active_session_token)
    refresh_token = create_refresh_token(str(user.id))

    # Pour l'app mobile, retourner directement les tokens (pas de redirect)
    if platform == 'mobile':
        return JSONResponse({
            "success": True,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": str(user.id),
                "email": user.email,
                "role": user.role,
                "verified": user.verified,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
            "redirect": state,
        })

    # Stocker les tokens côté serveur et générer un code d'échange sécurisé
    # Évite d'exposer les JWT dans l'URL (risque de fuite dans l'historique/logs)
    from services.token_exchange import store_tokens_for_exchange
    exchange_code = await store_tokens_for_exchange(
        access_token=access_token,
        refresh_token=refresh_token,
        user_id=str(user.id),
        expires_in_seconds=60  # Code valide 60 secondes
    )

    # Rediriger vers le frontend avec seulement le code d'échange
    from urllib.parse import urlencode
    params = urlencode({
        "code": exchange_code,
        "redirect": state,
    })
    return RedirectResponse(f"{settings.app_url}/auth/callback?{params}")


@router.post("/change-password")
async def change_password(
    data: PasswordChange,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Changer le mot de passe de l'utilisateur connecté.
    Vérifie l'ancien mot de passe avant d'appliquer le nouveau.
    """
    # Vérifier l'ancien mot de passe
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe actuel est incorrect",
        )

    # Hasher et sauvegarder le nouveau mot de passe
    current_user.hashed_password = hash_password(data.new_password)
    await db.flush()

    return {"message": "Mot de passe modifié avec succès"}


@router.get("/notifications")
async def get_my_notifications(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Récupérer les notifications de l'utilisateur connecté.
    Inclut les notifications globales (user_id NULL) et personnelles.
    """
    from sqlalchemy import or_
    from models.notification import Notification

    result = await db.execute(
        select(Notification)
        .where(
            or_(
                Notification.user_id == current_user.id,
                Notification.user_id.is_(None),
            )
        )
        .order_by(Notification.created_at.desc())
        .limit(50)
    )
    notifications = result.scalars().all()

    return {
        "notifications": [
            {
                "id": str(n.id),
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "is_read": n.is_read,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in notifications
        ],
    }


@router.put("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Marquer une notification comme lue.
    """
    from models.notification import Notification
    from uuid import UUID as PyUUID

    result = await db.execute(
        select(Notification).where(Notification.id == PyUUID(notification_id))
    )
    notification = result.scalar_one_or_none()

    if not notification:
        raise HTTPException(status_code=404, detail="Notification non trouvée")

    notification.is_read = True
    await db.flush()

    return {"message": "Notification marquée comme lue"}


@router.post("/logout")
async def logout(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Déconnecter l'utilisateur en supprimant son token de session actif.
    Permet de libérer la session pour se connecter sur un autre appareil.
    """
    current_user.active_session_token = None
    await db.flush()
    return {"message": "Déconnexion réussie"}


@router.delete("/me")
async def delete_account(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Supprimer le compte de l'utilisateur connecté (RGPD).
    Supprime définitivement toutes les données associées.
    """
    from sqlalchemy import delete as sa_delete
    from models.analysis import Analysis
    from models.subscription import Subscription
    from models.invoice import Invoice
    from sqlalchemy import update as sa_update
    from models.log import Log
    from models.notification import Notification

    user_id = current_user.id

    # Supprimer toutes les données liées avant de supprimer l'utilisateur
    await db.execute(sa_delete(Subscription).where(Subscription.user_id == user_id))
    await db.execute(sa_delete(Analysis).where(Analysis.user_id == user_id))
    await db.execute(sa_delete(Invoice).where(Invoice.user_id == user_id))
    await db.execute(sa_update(Log).where(Log.user_id == user_id).values(user_id=None))
    await db.execute(sa_delete(Notification).where(Notification.user_id == user_id))

    await db.delete(current_user)
    await db.flush()

    return {"message": "Compte supprimé avec succès"}


@router.post("/exchange-token")
async def exchange_token(exchange_code: str = Body(..., embed=True)):
    """
    Échanger un code temporaire contre les tokens JWT.
    
    Cet endpoint est utilisé après une connexion OAuth Google.
    Le code est à usage unique et expire après 60 secondes.
    """
    from services.token_exchange import exchange_code_for_tokens
    
    tokens = await exchange_code_for_tokens(exchange_code)
    
    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Code invalide ou expiré",
        )
    
    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "token_type": "bearer",
    }
