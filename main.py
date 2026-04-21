# === Point d'entrée principal de l'API Secure IA ===
# Ce fichier configure et lance l'application FastAPI
# Il enregistre toutes les routes et les middlewares

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import time
import os
import sys
import asyncio
from collections import defaultdict

from config import settings
from database import init_db

# --- Rate Limiting simple (en mémoire) ---
# Pour production, utiliser Redis
rate_limit_storage = defaultdict(list)  # ip -> [timestamps]
RATE_LIMIT_REQUESTS = 30  # Requêtes par fenêtre
RATE_LIMIT_WINDOW = 60    # Fenêtre en secondes

def is_rate_limited(key: str, max_requests: int = None, window_seconds: int = None) -> bool:
    """Vérifier si une clé (IP ou autre) a dépassé la limite de requêtes."""
    max_requests = max_requests or RATE_LIMIT_REQUESTS
    window_seconds = window_seconds or RATE_LIMIT_WINDOW
    
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=window_seconds)
    
    # Nettoyer les anciennes entrées
    rate_limit_storage[key] = [t for t in rate_limit_storage[key] if t > window_start]
    
    # Vérifier la limite
    if len(rate_limit_storage[key]) >= max_requests:
        return True
    
    # Ajouter la requête actuelle
    rate_limit_storage[key].append(now)
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestion du cycle de vie de l'application.
    - Au démarrage : initialiser la base de données et le logging
    - À l'arrêt : nettoyer les ressources
    """
    # --- Démarrage ---
    import logging
    from utils.database_logger import log_system
    
    logger = logging.getLogger('system')
    
    print("[*] Demarrage de Secure IA...")
    try:
        await init_db()
        print("[OK] Base de donnees initialisee")
        logger.info("[SYSTEM] Base de donnees initialisee avec succes")
        await log_system("Base de données initialisée avec succès")

        # Initialiser la configuration par défaut
        from database import async_session
        from services.config_helper import init_default_config
        async with async_session() as session:
            await init_default_config(session)
            await session.commit()
        print("[OK] Configuration par defaut initialisee")
        logger.info("[SYSTEM] Configuration par defaut initialisee")
        await log_system("Configuration par défaut initialisée")
        
        # Initialiser le logging vers la base de données
        from utils.database_logger import setup_database_logging
        setup_database_logging()
        logger.info("[SYSTEM] Logger initialisé")
        await log_system("Secure IA démarré avec succès - Logger actif", level="info")
        
    except Exception as e:
        print(f"[WARN] Erreur base de donnees : {e}")
        print("  ERREUR CRITIQUE: Base de données requise pour le fonctionnement")
        logger.error(f"[SYSTEM] ERREUR CRITIQUE: {e}")
        try:
            await log_system(f"ERREUR CRITIQUE au démarrage: {str(e)[:200]}", level="critical")
        except:
            pass

    yield  # L'application tourne ici

    # --- Arrêt ---
    print("[*] Arret de Secure IA...")
    logger.info("[SYSTEM] Arret de Secure IA")


# --- Créer l'application FastAPI ---
app = FastAPI(
    title="Secure IA API",
    description=(
        "API de la plateforme Secure IA pour la vérification "
        "et l'authentification de contenus numériques."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",        # Documentation Swagger UI
    redoc_url="/redoc",      # Documentation ReDoc
)

# --- Configurer CORS (origines restrictives) ---
# En production, seule l'URL de l'application est autorisée
# En développement, localhost est aussi autorisé
_ALLOWED_ORIGINS = [
    settings.app_url,
]

# Ajouter localhost seulement en mode debug
if settings.debug:
    _ALLOWED_ORIGINS.extend([
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ])

# Ajouter les origines pour les apps mobiles Capacitor
_ALLOWED_ORIGINS.extend([
    "capacitor://localhost",
    "http://localhost",
    "https://localhost",
])

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-Requested-With",
        "Accept",
        "Origin",
    ],
    expose_headers=["X-Process-Time"],
    max_age=600,  # Cache preflight 10 minutes
)


# --- Middleware Logger des erreurs ---
import traceback
import sys

@app.middleware("http")
async def error_logging_middleware(request: Request, call_next):
    """Logger toutes les erreurs 500 avec traceback complet - NE FAIT PAS CRASHER LE SERVEUR."""
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"❌ ERREUR 500 sur {request.method} {request.url.path}")
        print(f"{'='*60}")
        print(f"Type: {type(e).__name__}")
        print(f"Message: {str(e)}")
        print(f"\nTraceback:")
        traceback.print_exc()
        print(f"{'='*60}\n")
        # Retourner une réponse d'erreur JSON au lieu de crasher le serveur
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Une erreur interne est survenue",
                "error_type": type(e).__name__,
                "path": request.url.path,
                "timestamp": str(datetime.utcnow())
            }
        )


# --- Middleware Rate Limiting ---
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Limiter les requêtes par IP (30 req/minute)."""
    # Ignorer pour les endpoints de documentation
    if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
        return await call_next(request)
    
    # Limiter plus strictement sur /api/auth/login (10 req/min)
    client_ip = request.client.host
    is_login = request.url.path == "/api/auth/login" and request.method == "POST"
    
    if is_login:
        # Check spécial pour login (10 req/minute)
        login_key = f"login_{client_ip}"
        if is_rate_limited(login_key, max_requests=10, window_seconds=60):
            return JSONResponse(
                status_code=429,
                content={"detail": "Trop de tentatives. Réessayez dans une minute."}
            )
    # Limiter les routes admin (GET: 60 req/min, POST/PUT/DELETE: 10 req/min)
    is_admin_route = request.url.path.startswith("/api/admin")
    if is_admin_route:
        admin_key = f"admin_{client_ip}_{request.method}"
        # Plus permissif pour les GET (lecture), strict pour modifications
        max_requests = 60 if request.method == "GET" else 10
        if is_rate_limited(admin_key, max_requests=max_requests, window_seconds=60):
            return JSONResponse(
                status_code=429,
                content={"detail": "Trop de requêtes admin. Réessayez plus tard."}
            )
    else:
        # Limite générale: 60 req/minute par IP (augmenté pour éviter les faux positifs)
        if is_rate_limited(client_ip, max_requests=60, window_seconds=60):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please slow down."}
            )
    
    return await call_next(request)


# --- Middleware de sécurité (CSP, HSTS, etc.) ---
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Ajouter les en-têtes de sécurité recommandés.
    - CSP: Content Security Policy
    - HSTS: HTTP Strict Transport Security (production)
    - X-Frame-Options: Protection clickjacking
    - X-Content-Type-Options: Protection MIME sniffing
    - Referrer-Policy: Contrôle du referrer
    """
    response = await call_next(request)
    
    # Content Security Policy (CSP) - restrictive
    csp_directives = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",  # Nécessaire pour React
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",  # Équivalent à X-Frame-Options: DENY
        "base-uri 'self'",
        "form-action 'self'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
    
    # X-Frame-Options: Protection contre le clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    
    # X-Content-Type-Options: Empêche le MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # X-XSS-Protection: Protection XSS (legacy, mais utile)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Referrer-Policy: Limite les informations envoyées
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Permissions-Policy: Limite les fonctionnalités navigateur
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), "
        "payment=(), usb=(), magnetometer=(), gyroscope=()"
    )
    
    # Strict-Transport-Security (HSTS) - uniquement en production HTTPS
    if not settings.debug and request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )
    
    return response


# --- Middleware pour mesurer le temps de réponse ---
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """
    Ajouter le temps de traitement dans le header de réponse.
    Utile pour le monitoring des performances.
    """
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time, 4))
    return response


# --- Enregistrer toutes les routes ---
from routes.auth import router as auth_router
from routes.analysis import router as analysis_router
from routes.admin import router as admin_router
from routes.payment import router as payment_router
from routes.public import router as public_router

app.include_router(auth_router)       # Routes d'authentification
app.include_router(analysis_router)   # Routes d'analyse
app.include_router(admin_router)      # Routes d'administration
app.include_router(payment_router)    # Routes de paiement Stripe
app.include_router(public_router)     # Routes publiques (config, offres)


# --- Route racine (health check) ---
@app.get("/", tags=["Système"])
async def root():
    """
    Point d'entrée racine de l'API.
    Utilisé pour vérifier que l'API est en ligne.
    """
    return {
        "name": "Secure IA API",
        "version": "2.0.0",
        "status": "en ligne",
        "documentation": "/docs",
    }


@app.get("/api/health", tags=["Système"])
async def health_check():
    """
    Vérification de santé de l'API.
    Vérifie que tous les services sont opérationnels.
    """
    return {
        "status": "ok",
        "services": {
            "api": "opérationnel",
            "database": "vérification nécessaire",
            "redis": "vérification nécessaire",
        },
    }


# --- Gestionnaire d'erreurs global ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Capturer toutes les erreurs non gérées.
    Retourne une réponse JSON propre au lieu d'un crash.
    """
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Une erreur interne est survenue. Notre équipe a été notifiée. Veuillez réessayer dans quelques instants.",
            "message": str(exc) if settings.debug else "Erreur serveur",
        },
    )
