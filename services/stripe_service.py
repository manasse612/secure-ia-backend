# === Service de paiement Stripe ===
# Gère les abonnements, les paiements et les webhooks Stripe
# Permet de créer, modifier et annuler des abonnements Pro/Business

import logging
import stripe
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from config import settings
from models.user import User
from models.subscription import Subscription
from models.invoice import Invoice

logger = logging.getLogger(__name__)

# Configurer la clé API Stripe
stripe.api_key = settings.stripe_secret_key if hasattr(settings, 'stripe_secret_key') and settings.stripe_secret_key else None


# --- Créer un client Stripe pour un utilisateur ---
async def create_stripe_customer(db: AsyncSession, user: User) -> Optional[str]:
    """
    Crée un client dans Stripe et sauvegarde l'ID dans la base de données.
    Retourne l'ID du client Stripe.
    """
    if not stripe.api_key:
        raise RuntimeError(
            "STRIPE_SECRET_KEY non configurée. "
            "Veuillez configurer Stripe dans le fichier .env"
        )

    try:
        # Créer le client dans Stripe
        customer = stripe.Customer.create(
            email=user.email,
            name=user.full_name or user.email,
            metadata={"user_id": str(user.id)},
        )

        # Sauvegarder l'ID client dans l'abonnement
        stmt = (
            update(Subscription)
            .where(Subscription.user_id == user.id)
            .values(stripe_customer_id=customer.id)
        )
        await db.execute(stmt)
        await db.flush()

        return customer.id

    except stripe.error.StripeError as e:
        print(f"Erreur Stripe : {e}")
        return None


# --- Créer une session de paiement (Checkout) ---
async def create_checkout_session(
    db: AsyncSession,
    user: User,
    plan: str,
) -> Optional[dict]:
    """
    Crée une session Stripe Checkout pour qu'un utilisateur puisse s'abonner.
    Retourne l'URL de la page de paiement Stripe.
    """
    # Déterminer le prix selon le plan
    price_ids = {
        "pro": getattr(settings, 'stripe_price_pro', None),
        "business": getattr(settings, 'stripe_price_business', None),
    }

    price_id = price_ids.get(plan)

    if not stripe.api_key or not price_id:
        raise RuntimeError(
            "STRIPE_SECRET_KEY ou STRIPE_PRICE non configurés. "
            "Veuillez configurer Stripe dans le fichier .env"
        )

    try:
        # Récupérer ou créer le client Stripe
        sub_query = select(Subscription).where(Subscription.user_id == user.id)
        sub_result = await db.execute(sub_query)
        subscription = sub_result.scalar_one_or_none()

        customer_id = subscription.stripe_customer_id if subscription else None
        if not customer_id:
            customer_id = await create_stripe_customer(db, user)

        # Créer la session Checkout
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=f"{settings.app_url}/payment/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{settings.app_url}/payment/cancel",
            metadata={"user_id": str(user.id), "plan": plan},
        )

        return {
            "checkout_url": session.url,
            "session_id": session.id,
            "mode": "live",
        }

    except stripe.error.StripeError as e:
        print(f"Erreur Stripe Checkout : {e}")
        return None


# --- Gérer le webhook Stripe (paiement réussi) ---
async def handle_checkout_completed(
    db: AsyncSession,
    session_data: dict,
) -> bool:
    """
    Appelé quand un paiement Stripe est confirmé.
    Met à jour l'abonnement de l'utilisateur dans la base de données.
    """
    try:
        user_id = session_data.get("metadata", {}).get("user_id")
        plan = session_data.get("metadata", {}).get("plan", "pro")
        stripe_subscription_id = session_data.get("subscription")

        if not user_id:
            return False

        # Déterminer les limites selon le plan
        plan_limits = {
            "pro": {"max": "500", "price": 29.90},
            "business": {"max": "5000", "price": 99.90},
        }
        limits = plan_limits.get(plan, plan_limits["pro"])

        # Mettre à jour l'abonnement
        stmt = (
            update(Subscription)
            .where(Subscription.user_id == user_id)
            .values(
                plan=plan,
                status="active",
                price_monthly=limits["price"],
                max_analyses_per_month=limits["max"],
                stripe_subscription_id=stripe_subscription_id,
            )
        )
        await db.execute(stmt)

        # Mettre à jour le rôle de l'utilisateur
        role_map = {"pro": "pro", "business": "business"}
        new_role = role_map.get(plan, "free")
        stmt_user = (
            update(User)
            .where(User.id == user_id)
            .values(role=new_role)
        )
        await db.execute(stmt_user)

        await db.flush()
        return True

    except Exception as e:
        logger.error(f"Erreur webhook Stripe : {type(e).__name__}")
        await db.rollback()
        return False


# --- Annuler un abonnement ---
async def cancel_subscription(
    db: AsyncSession,
    user: User,
) -> bool:
    """
    Annule l'abonnement Stripe d'un utilisateur.
    Rétrograde le plan vers 'free' à la fin de la période.
    """
    try:
        # Récupérer l'abonnement
        sub_query = select(Subscription).where(Subscription.user_id == user.id)
        sub_result = await db.execute(sub_query)
        subscription = sub_result.scalar_one_or_none()

        if not subscription:
            return False

        # Annuler dans Stripe si c'est un vrai abonnement
        if stripe.api_key and subscription.stripe_subscription_id:
            try:
                stripe.Subscription.modify(
                    subscription.stripe_subscription_id,
                    cancel_at_period_end=True,
                )
            except stripe.error.StripeError as e:
                print(f"Erreur annulation Stripe : {e}")

        # Marquer comme annulé dans la base de données
        from datetime import datetime
        stmt = (
            update(Subscription)
            .where(Subscription.user_id == user.id)
            .values(
                status="cancelled",
                cancelled_at=datetime.utcnow(),
            )
        )
        await db.execute(stmt)

        # Rétrograder le rôle de l'utilisateur
        stmt_user = (
            update(User)
            .where(User.id == user.id)
            .values(role="free")
        )
        await db.execute(stmt_user)

        await db.flush()
        return True

    except Exception as e:
        logger.error(f"Erreur annulation : {type(e).__name__}")
        await db.rollback()
        return False


# --- Obtenir le portail client Stripe ---
async def create_customer_portal_session(
    db: AsyncSession,
    user: User,
) -> Optional[str]:
    """
    Crée une session de portail client Stripe.
    Permet à l'utilisateur de gérer son abonnement et ses factures.
    """
    if not stripe.api_key:
        raise RuntimeError(
            "STRIPE_SECRET_KEY non configurée. "
            "Veuillez configurer Stripe dans le fichier .env"
        )

    try:
        sub_query = select(Subscription).where(Subscription.user_id == user.id)
        sub_result = await db.execute(sub_query)
        subscription = sub_result.scalar_one_or_none()

        if not subscription or not subscription.stripe_customer_id:
            return None

        session = stripe.billing_portal.Session.create(
            customer=subscription.stripe_customer_id,
            return_url=f"{settings.app_url}/profile",
        )

        return session.url

    except stripe.error.StripeError as e:
        print(f"Erreur portail Stripe : {e}")
        return None
