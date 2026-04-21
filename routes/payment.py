# === Routes de paiement Stripe ===
# Gère les endpoints pour les abonnements, le checkout et les webhooks
# Permet aux utilisateurs de passer à un plan payant

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.user import User
from utils.security import get_current_user
from services.stripe_service import (
    create_checkout_session,
    handle_checkout_completed,
    cancel_subscription,
    create_customer_portal_session,
)
from config import settings

# Créer le routeur pour les routes de paiement
router = APIRouter(prefix="/api/payment", tags=["Paiement"])


# --- Créer une session de paiement Checkout ---
@router.post("/checkout")
async def checkout(
    plan: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Crée une session Stripe Checkout pour s'abonner à un plan.
    Plan accepté : 'pro' ou 'business'.
    Retourne l'URL de paiement.
    """
    # Vérifier que le plan est valide
    if plan not in ["pro", "business"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Plan invalide. Choisissez 'pro' ou 'business'.",
        )

    # Créer la session de paiement
    try:
        result = await create_checkout_session(db, current_user, plan)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    if not result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la création de la session de paiement.",
        )

    return result


# --- Webhook Stripe (appelé par Stripe après un paiement) ---
@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint appelé par Stripe pour notifier des événements.
    Vérifie la signature du webhook et traite les paiements confirmés.
    Protection idempotente : un événement n'est traité qu'une seule fois.
    """
    from services.stripe_idempotency import (
        is_event_processed,
        mark_event_processed,
        get_event_processing_result,
    )
    
    # Récupérer le body de la requête
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    # Vérifier la signature (si webhook secret configuré)
    webhook_secret = getattr(settings, 'stripe_webhook_secret', None)

    if webhook_secret and sig_header:
        try:
            import stripe
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        except (ValueError, stripe.error.SignatureVerificationError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signature webhook invalide.",
            )
    else:
        # Mode développement : parser le JSON directement
        import json
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Payload invalide.",
            )

    # --- Protection Idempotence ---
    # Vérifier si cet événement a déjà été traité
    if await is_event_processed(event):
        # Renvoyer le même résultat que précédemment
        previous_result = await get_event_processing_result(event)
        return {
            "status": "already_processed",
            "event_type": event.get("type"),
            "message": "Cet événement a déjà été traité",
            "previous_result": previous_result,
        }

    # Traiter l'événement selon son type
    event_type = event.get("type", "")
    processing_result = {"success": True}

    if event_type == "checkout.session.completed":
        # Paiement confirmé : mettre à jour l'abonnement
        session_data = event.get("data", {}).get("object", {})
        success = await handle_checkout_completed(db, session_data)
        if not success:
            processing_result = {"success": False, "error": "checkout_failed"}
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Erreur lors du traitement du paiement.",
            )

    # Marquer l'événement comme traité (avec le résultat)
    await mark_event_processed(event, processing_result)

    return {"status": "ok", "event_type": event_type}


# --- Annuler un abonnement ---
@router.post("/cancel")
async def cancel(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Annule l'abonnement de l'utilisateur connecté.
    Rétrograde vers le plan gratuit.
    """
    success = await cancel_subscription(db, current_user)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible d'annuler l'abonnement.",
        )

    return {"message": "Abonnement annulé. Vous serez rétrogradé en fin de période."}


# --- Portail client Stripe ---
@router.get("/portal")
async def customer_portal(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retourne l'URL du portail client Stripe.
    Permet de gérer les factures et moyens de paiement.
    """
    portal_url = await create_customer_portal_session(db, current_user)

    if not portal_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible de créer le portail client.",
        )

    return {"portal_url": portal_url}
