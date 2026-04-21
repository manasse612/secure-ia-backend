# === Client API robuste avec retry et circuit breaker ===
# Fournit une abstraction pour les appels API externes avec:
# - Retry automatique avec backoff exponentiel
# - Circuit breaker pour éviter les cascades de défaillances
# - Logging détaillé
# - Timeout configurables

import asyncio
import httpx
import time
from typing import Optional, Callable, Any
from functools import wraps
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """États du circuit breaker."""
    CLOSED = "closed"      # Fonctionnement normal
    OPEN = "open"          # Circuit ouvert, rejette les appels
    HALF_OPEN = "half_open"  # Test si le service est rétabli


class CircuitBreaker:
    """
    Circuit breaker pour protéger les appels API externes.
    
    - CLOSED: les appels passent normalement
    - OPEN: les appels échouent immédiatement (après N erreurs)
    - HALF_OPEN: teste si le service est rétabli
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 3,
        name: str = "default"
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        self.name = name
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()
    
    @property
    def state(self) -> CircuitState:
        return self._state
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Exécuter une fonction avec protection du circuit breaker."""
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if time.time() - self._last_failure_time >= self.recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
                    logger.info(f"[{self.name}] Circuit breaker: OPEN -> HALF_OPEN")
                else:
                    raise CircuitBreakerOpen(f"Circuit breaker ouvert pour {self.name}")
            
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitBreakerOpen(f"Circuit breaker half-open limit reached for {self.name}")
                self._half_open_calls += 1
        
        # Exécuter la fonction
        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception as e:
            await self._on_failure()
            raise
    
    async def _on_success(self):
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.half_open_max_calls:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"[{self.name}] Circuit breaker: HALF_OPEN -> CLOSED")
            else:
                self._failure_count = 0
    
    async def _on_failure(self):
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning(f"[{self.name}] Circuit breaker: HALF_OPEN -> OPEN")
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.warning(f"[{self.name}] Circuit breaker: CLOSED -> OPEN (failures: {self._failure_count})")


class CircuitBreakerOpen(Exception):
    """Exception levée quand le circuit breaker est ouvert."""
    pass


# Instances globales des circuit breakers
_hive_circuit = CircuitBreaker(failure_threshold=3, recovery_timeout=30.0, name="hive_ai")
_openai_circuit = CircuitBreaker(failure_threshold=3, recovery_timeout=30.0, name="openai")
_virustotal_circuit = CircuitBreaker(failure_threshold=5, recovery_timeout=60.0, name="virustotal")


def with_retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 10.0,
    exponential_base: float = 2.0,
    retryable_exceptions: tuple = (httpx.TimeoutException, httpx.NetworkError, httpx.ConnectError)
):
    """
    Décorateur pour retry avec backoff exponentiel.
    
    Args:
        max_retries: Nombre maximum de tentatives
        base_delay: Délai initial entre les tentatives
        max_delay: Délai maximum entre les tentatives
        exponential_base: Base pour le calcul exponentiel
        retryable_exceptions: Exceptions qui déclenchent un retry
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = min(base_delay * (exponential_base ** attempt), max_delay)
                        logger.warning(
                            f"[{func.__name__}] Tentative {attempt + 1}/{max_retries + 1} échouée: {e}. "
                            f"Retry dans {delay:.1f}s..."
                        )
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"[{func.__name__}] Toutes les tentatives échouées")
                        raise
                except Exception:
                    # Exceptions non retryable, propager immédiatement
                    raise
            
            raise last_exception
        return wrapper
    return decorator


async def safe_api_call(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    circuit_breaker: CircuitBreaker,
    **kwargs
) -> httpx.Response:
    """
    Effectuer un appel API avec circuit breaker et retry intégrés.
    
    Args:
        client: Client HTTPX async
        method: Méthode HTTP (GET, POST, etc.)
        url: URL de l'API
        circuit_breaker: Instance de CircuitBreaker
        **kwargs: Arguments supplémentaires pour la requête
    
    Returns:
        Réponse HTTP
    
    Raises:
        CircuitBreakerOpen: Si le circuit est ouvert
        httpx.HTTPStatusError: Si le statut HTTP est une erreur
    """
    async def _make_request():
        response = await client.request(method, url, **kwargs)
        response.raise_for_status()
        return response
    
    # Wrapper avec retry
    @with_retry(max_retries=3, base_delay=1.0)
    async def _call_with_retry():
        return await _make_request()
    
    # Appel avec circuit breaker
    return await circuit_breaker.call(_call_with_retry)


# Fonctions utilitaires spécifiques pour chaque API

async def hive_api_call(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs
) -> httpx.Response:
    """Appel API Hive AI avec protection."""
    return await safe_api_call(client, method, url, _hive_circuit, **kwargs)


async def openai_api_call(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs
) -> httpx.Response:
    """Appel API OpenAI avec protection."""
    return await safe_api_call(client, method, url, _openai_circuit, **kwargs)


async def virustotal_api_call(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    **kwargs
) -> httpx.Response:
    """Appel API VirusTotal avec protection."""
    return await safe_api_call(client, method, url, _virustotal_circuit, **kwargs)


# Validation des fichiers

ALLOWED_IMAGE_TYPES = {
    "image/jpeg": (".jpg", ".jpeg"),
    "image/png": (".png",),
    "image/gif": (".gif",),
    "image/webp": (".webp",),
    "image/bmp": (".bmp",),
}

ALLOWED_VIDEO_TYPES = {
    "video/mp4": (".mp4",),
    "video/webm": (".webm",),
    "video/ogg": (".ogg", ".ogv"),
    "video/quicktime": (".mov",),
    "video/x-msvideo": (".avi",),
    "video/x-matroska": (".mkv",),
}

MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10 Mo
MAX_VIDEO_SIZE = 30 * 1024 * 1024  # 30 Mo


def validate_image_file(content_type: str, size: int, filename: str) -> tuple[bool, str]:
    """
    Valider un fichier image.
    
    Returns:
        (is_valid, error_message)
    """
    if content_type not in ALLOWED_IMAGE_TYPES:
        allowed = ", ".join(ALLOWED_IMAGE_TYPES.keys())
        return False, f"Type de fichier non supporté: {content_type}. Types acceptés: {allowed}"
    
    if size > MAX_IMAGE_SIZE:
        return False, f"Fichier trop volumineux: {size / (1024*1024):.1f} Mo. Maximum: {MAX_IMAGE_SIZE / (1024*1024):.0f} Mo"
    
    # Vérifier l'extension
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    allowed_exts = ALLOWED_IMAGE_TYPES.get(content_type, ())
    if ext and f".{ext}" not in allowed_exts:
        return False, f"Extension de fichier non correspondante: .{ext}"
    
    return True, ""


def validate_video_file(content_type: str, size: int, filename: str) -> tuple[bool, str]:
    """
    Valider un fichier vidéo.
    
    Returns:
        (is_valid, error_message)
    """
    if content_type not in ALLOWED_VIDEO_TYPES:
        allowed = ", ".join(ALLOWED_VIDEO_TYPES.keys())
        return False, f"Type de fichier non supporté: {content_type}. Types acceptés: {allowed}"
    
    if size > MAX_VIDEO_SIZE:
        return False, f"Fichier trop volumineux: {size / (1024*1024):.1f} Mo. Maximum: {MAX_VIDEO_SIZE / (1024*1024):.0f} Mo"
    
    # Vérifier l'extension
    ext = filename.lower().split(".")[-1] if "." in filename else ""
    allowed_exts = ALLOWED_VIDEO_TYPES.get(content_type, ())
    if ext and f".{ext}" not in allowed_exts:
        return False, f"Extension de fichier non correspondante: .{ext}"
    
    return True, ""


# Utilitaires de sécurité

def sanitize_filename(filename: str) -> str:
    """
    Nettoyer un nom de fichier pour éviter les injections de path.
    
    Returns:
        Nom de fichier sécurisé
    """
    import os
    import re
    
    # Extraire le nom de base
    filename = os.path.basename(filename)
    
    # Remplacer les caractères dangereux
    filename = re.sub(r'[^\w.\-]', '_', filename)
    
    # Limiter la longueur
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:250] + ext
    
    return filename


def mask_api_key(key: str) -> str:
    """Masquer une clé API pour le logging."""
    if not key:
        return "Non configurée"
    if len(key) <= 8:
        return "***"
    return key[:4] + "***" + key[-4:]
