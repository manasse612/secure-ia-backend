# === Service d'envoi d'emails ===
# Envoie les emails de vérification et de réinitialisation de mot de passe
# Utilise SMTP en production
# Logs sécurisés : les emails sont masqués pour protéger la privacy

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import settings

logger = logging.getLogger(__name__)


def _mask_email(email: str) -> str:
    """Masquer une adresse email pour les logs (privacy)."""
    if not email or '@' not in email:
        return '***'
    local, domain = email.split('@')
    masked_local = local[:2] + '***' if len(local) > 2 else '***'
    return f"{masked_local}@{domain}"


def _get_smtp_configured() -> bool:
    """Vérifier si le SMTP est configuré."""
    return bool(settings.smtp_host and settings.smtp_user and settings.smtp_password)


def _send_email(to_email: str, subject: str, html_body: str) -> bool:
    """
    Envoyer un email via SMTP.
    Retourne True si l'envoi a réussi, False sinon.
    """
    masked = _mask_email(to_email)
    
    if not _get_smtp_configured():
        logger.info(f"[EMAIL] SMTP non configuré — email non envoyé à {masked}")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_from_email}>"
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
            server.send_message(msg)

        logger.info(f"[EMAIL] Envoyé avec succès à {masked}")
        return True
    except smtplib.SMTPException as e:
        logger.error(f"[EMAIL] Erreur SMTP pour {masked}: {type(e).__name__}")
        return False
    except Exception as e:
        logger.error(f"[EMAIL] Erreur inattendue pour {masked}: {type(e).__name__}")
        return False


def send_verification_code(to_email: str, code: str, full_name: str = "") -> bool:
    """Envoyer un code de vérification d'email après inscription."""
    name = full_name or to_email
    subject = f"Secure IA — Votre code de vérification : {code}"
    html = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #f8fafc; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
            <div style="display: inline-block; background: #4f46e5; color: white; padding: 10px 16px; border-radius: 12px; font-weight: bold; font-size: 18px;">
                🛡️ Secure IA
            </div>
        </div>
        <div style="background: white; padding: 28px; border-radius: 10px; border: 1px solid #e2e8f0;">
            <h2 style="margin: 0 0 8px; color: #1e293b; font-size: 20px;">Bienvenue, {name} !</h2>
            <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin: 0 0 24px;">
                Merci de vous être inscrit sur Secure IA. Pour activer votre compte, entrez le code ci-dessous :
            </p>
            <div style="text-align: center; margin: 24px 0;">
                <div style="display: inline-block; background: #f1f5f9; padding: 16px 32px; border-radius: 10px; border: 2px dashed #4f46e5;">
                    <span style="font-family: monospace; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #4f46e5;">{code}</span>
                </div>
            </div>
            <p style="color: #94a3b8; font-size: 12px; text-align: center; margin: 0;">
                Ce code expire dans <strong>15 minutes</strong>. Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.
            </p>
        </div>
        <p style="color: #94a3b8; font-size: 11px; text-align: center; margin-top: 16px;">
            © 2026 Secure IA — Plateforme de vérification de contenus numériques
        </p>
    </div>
    """
    return _send_email(to_email, subject, html)


def send_password_reset_code(to_email: str, code: str) -> bool:
    """Envoyer un code de réinitialisation de mot de passe."""
    subject = f"Secure IA — Code de réinitialisation : {code}"
    html = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 30px; background: #f8fafc; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
            <div style="display: inline-block; background: #4f46e5; color: white; padding: 10px 16px; border-radius: 12px; font-weight: bold; font-size: 18px;">
                🛡️ Secure IA
            </div>
        </div>
        <div style="background: white; padding: 28px; border-radius: 10px; border: 1px solid #e2e8f0;">
            <h2 style="margin: 0 0 8px; color: #1e293b; font-size: 20px;">Réinitialisation du mot de passe</h2>
            <p style="color: #64748b; font-size: 14px; line-height: 1.6; margin: 0 0 24px;">
                Vous avez demandé à réinitialiser votre mot de passe. Voici votre code de vérification :
            </p>
            <div style="text-align: center; margin: 24px 0;">
                <div style="display: inline-block; background: #fef2f2; padding: 16px 32px; border-radius: 10px; border: 2px dashed #ef4444;">
                    <span style="font-family: monospace; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #ef4444;">{code}</span>
                </div>
            </div>
            <p style="color: #94a3b8; font-size: 12px; text-align: center; margin: 0;">
                Ce code expire dans <strong>15 minutes</strong>. Si vous n'avez pas fait cette demande, ignorez cet email et votre mot de passe restera inchangé.
            </p>
        </div>
        <p style="color: #94a3b8; font-size: 11px; text-align: center; margin-top: 16px;">
            © 2026 Secure IA — Plateforme de vérification de contenus numériques
        </p>
    </div>
    """
    return _send_email(to_email, subject, html)
