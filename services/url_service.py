# === Service d'analyse d'URLs ===
# Vérifie la sécurité et la réputation d'un site web
# Utilise l'API VirusTotal pour le scan de réputation
# Vérifie le certificat SSL, les blacklists, et les informations WHOIS

import time
import httpx
import ssl
import socket
import logging
from urllib.parse import urlparse
from typing import Optional

from config import settings
from services.api_client import virustotal_api_call, CircuitBreakerOpen, with_retry

logger = logging.getLogger(__name__)


async def analyze_url(url: str) -> dict:
    """
    Analyser la sécurité d'une URL / site web.
    
    Étapes :
    1. Vérifier le format de l'URL
    2. Vérifier le certificat SSL
    3. Scanner via VirusTotal (réputation, malwares)
    4. Analyser les en-têtes HTTP de sécurité
    5. Calculer le score de sécurité global
    
    Paramètres :
    - url : l'URL du site à analyser
    
    Retourne un dictionnaire avec les résultats détaillés.
    """
    start_time = time.time()
    results = {
        "url_info": {},
        "ssl_check": {},
        "security_headers": {},
        "virustotal": {},
        "score": 0.0,
        "verdict": "non_verifiable",
        "summary": "",
    }

    # --- Étape 1 : Analyser l'URL ---
    url_info = _parse_url(url)
    results["url_info"] = url_info

    if url_info.get("error"):
        raise ValueError(f"URL invalide : {url_info['error']}")

    # --- Étape 2 : Vérifier le SSL ---
    try:
        ssl_result = await _check_ssl(url_info["hostname"])
        results["ssl_check"] = ssl_result
    except Exception as e:
        results["ssl_check"] = {"error": str(e), "has_ssl": False}

    # --- Étape 3 : Scanner via VirusTotal ---
    try:
        vt_result = await _scan_with_virustotal(url)
        results["virustotal"] = vt_result
    except RuntimeError as e:
        # Configuration error - on propage l'erreur pour bloquer l'analyse
        raise RuntimeError(f"Service d'analyse indisponible : {str(e)}")
    except Exception as e:
        results["virustotal"] = {"error": str(e)}

    # --- Étape 4 : Vérifier les en-têtes de sécurité ---
    try:
        headers_result = await _check_security_headers(url)
        results["security_headers"] = headers_result
    except Exception as e:
        results["security_headers"] = {"error": str(e)}

    # --- Étape 4b : Vérifier si VirusTotal a échoué ---
    if results["virustotal"].get("error"):
        raise RuntimeError(f"Analyse impossible : {results['virustotal']['error']}")

    # --- Étape 5 : Calculer le score ---
    score = _calculate_url_score(results)
    results["score"] = score

    # --- Étape 6 : Verdict ---
    if score >= 70:
        results["verdict"] = "securise"
    elif score >= 40:
        results["verdict"] = "risque_modere"
    else:
        results["verdict"] = "dangereux"

    # --- Étape 7 : Résumé ---
    results["summary"] = _generate_url_summary(results)
    results["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)

    return results


def _parse_url(url: str) -> dict:
    """
    Analyser et valider le format d'une URL.
    Extrait le protocole, le nom de domaine, le chemin, etc.
    """
    try:
        # Ajouter https:// si pas de protocole
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)

        if not parsed.hostname:
            return {"error": "Nom de domaine manquant"}

        return {
            "full_url": url,
            "scheme": parsed.scheme,
            "hostname": parsed.hostname,
            "port": parsed.port,
            "path": parsed.path or "/",
            "is_https": parsed.scheme == "https",
        }
    except Exception as e:
        return {"error": f"URL invalide : {str(e)}"}


async def _check_ssl(hostname: str) -> dict:
    """
    Vérifier le certificat SSL du site.
    - Vérifie si le certificat est valide et non expiré
    - Extrait les informations du certificat (émetteur, dates)
    """
    result = {
        "has_ssl": False,
        "valid": False,
        "issuer": None,
        "expires": None,
        "protocol": None,
    }

    try:
        # Créer un contexte SSL
        context = ssl.create_default_context()

        # Se connecter au serveur
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["has_ssl"] = True
                result["valid"] = True
                result["protocol"] = ssock.version()

                # Extraire les informations du certificat
                if cert:
                    # Émetteur du certificat
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    result["issuer"] = issuer.get("organizationName", "Inconnu")

                    # Date d'expiration
                    result["expires"] = cert.get("notAfter", "Inconnue")

    except ssl.SSLCertVerificationError:
        result["has_ssl"] = True
        result["valid"] = False
        result["error"] = "Certificat SSL invalide ou expiré"
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["has_ssl"] = False
        result["error"] = "Impossible de vérifier le SSL (connexion refusée)"

    return result


async def _scan_with_virustotal(url: str) -> dict:
    """
    Scanner l'URL avec VirusTotal pour détecter les menaces.
    - Vérifie la réputation du site
    - Détecte les malwares, phishing, etc.
    """
    if not settings.virustotal_api_key:
        raise RuntimeError(
            "VIRUSTOTAL_API_KEY non configurée. "
            "Veuillez configurer la clé API VirusTotal dans le fichier .env"
        )

    logger.info(f"[VirusTotal] Scan demandé pour: {url}")

    # Appel réel à l'API VirusTotal avec circuit breaker
    try:
        async with httpx.AsyncClient() as client:
            # Encoder l'URL en base64 pour l'ID VirusTotal
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

            headers = {"x-apikey": settings.virustotal_api_key}
            vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            response = await virustotal_api_call(
                client, "GET", vt_url,
                headers=headers,
                timeout=15,
            )

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            result = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attributes.get("reputation", 0),
                "categories": attributes.get("categories", {}),
                "last_analysis_date": attributes.get("last_analysis_date"),
            }
            logger.info(f"[VirusTotal] Scan terminé - Malicious: {result['malicious']}, Suspicious: {result['suspicious']}")
            return result

    except CircuitBreakerOpen:
        logger.error("[VirusTotal] Circuit breaker ouvert")
        return {
            "error": "Service VirusTotal temporairement indisponible. Réessayez plus tard.",
            "circuit_breaker_open": True,
        }
    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        logger.error(f"[VirusTotal] Erreur HTTP {status_code}")
        
        if status_code == 404:
            return {"info": "URL non encore analysée par VirusTotal"}
        elif status_code == 401:
            return {"error": "Clé API VirusTotal invalide. Vérifiez votre configuration."}
        elif status_code == 429:
            return {"error": "Limite de requêtes VirusTotal atteinte. Veuillez réessayer dans quelques minutes."}
        return {"error": f"Erreur API VirusTotal ({status_code})"}
    except Exception as e:
        logger.exception("[VirusTotal] Erreur inattendue")
        return {"error": f"Erreur de connexion VirusTotal : {str(e)}"}


async def _check_security_headers(url: str) -> dict:
    """
    Vérifier les en-têtes de sécurité HTTP du site.
    Les bons sites web incluent ces en-têtes pour protéger les visiteurs.
    """
    important_headers = {
        "strict-transport-security": "HSTS (force HTTPS)",
        "content-security-policy": "CSP (protection XSS)",
        "x-frame-options": "Protection clickjacking",
        "x-content-type-options": "Protection MIME",
        "x-xss-protection": "Protection XSS navigateur",
        "referrer-policy": "Politique de référent",
    }

    result = {
        "headers_found": [],
        "headers_missing": [],
        "score": 0,
    }

    try:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            response = await client.head(url, timeout=10)
            response_headers = {k.lower(): v for k, v in response.headers.items()}

            for header, description in important_headers.items():
                if header in response_headers:
                    result["headers_found"].append({
                        "name": header,
                        "description": description,
                        "value": response_headers[header][:100],
                    })
                else:
                    result["headers_missing"].append({
                        "name": header,
                        "description": description,
                    })

            # Score basé sur le nombre d'en-têtes trouvés
            total = len(important_headers)
            found = len(result["headers_found"])
            result["score"] = round((found / total) * 100, 1)

    except Exception as e:
        result["error"] = f"Impossible de vérifier les en-têtes : {str(e)}"

    return result


def _calculate_url_score(results: dict) -> float:
    """
    Calculer le score de sécurité global de l'URL (0 à 100).
    - 100 = site très sécurisé
    - 0 = site potentiellement dangereux
    """
    score = 50.0  # Score de départ

    # SSL (très important)
    ssl_check = results.get("ssl_check", {})
    if ssl_check.get("has_ssl") and ssl_check.get("valid"):
        score += 20
    elif ssl_check.get("has_ssl") and not ssl_check.get("valid"):
        score -= 10
    else:
        score -= 20

    # HTTPS
    url_info = results.get("url_info", {})
    if url_info.get("is_https"):
        score += 5

    # VirusTotal
    vt = results.get("virustotal", {})
    malicious = vt.get("malicious", 0)
    suspicious = vt.get("suspicious", 0)
    score -= malicious * 15
    score -= suspicious * 5

    # En-têtes de sécurité
    headers = results.get("security_headers", {})
    headers_score = headers.get("score", 0)
    score += (headers_score / 100) * 15

    # Limiter entre 0 et 100
    return round(max(0, min(100, score)), 1)


def _generate_url_summary(results: dict) -> str:
    """
    Générer un résumé en français de l'analyse de l'URL.
    """
    score = results.get("score", 0)
    verdict = results.get("verdict", "non_verifiable")
    ssl_check = results.get("ssl_check", {})
    vt = results.get("virustotal", {})

    lines = []

    # Verdict principal
    if verdict == "securise":
        lines.append("✅ Ce site web semble sécurisé.")
    elif verdict == "risque_modere":
        lines.append("⚠️ Ce site web présente des risques modérés.")
    else:
        lines.append("❌ Ce site web est potentiellement dangereux.")

    lines.append(f"Score de sécurité : {score}/100")

    # SSL
    if ssl_check.get("has_ssl") and ssl_check.get("valid"):
        lines.append(f"🔒 Certificat SSL valide (émis par {ssl_check.get('issuer', 'inconnu')})")
    elif ssl_check.get("has_ssl"):
        lines.append("⚠️ Certificat SSL présent mais invalide")
    else:
        lines.append("❌ Pas de certificat SSL (connexion non sécurisée)")

    # VirusTotal
    malicious = vt.get("malicious", 0)
    if malicious > 0:
        lines.append(f"🚨 {malicious} moteur(s) antivirus ont signalé ce site comme malveillant")
    else:
        lines.append("✅ Aucune détection malveillante par les moteurs antivirus")

    # En-têtes
    headers = results.get("security_headers", {})
    found_count = len(headers.get("headers_found", []))
    missing_count = len(headers.get("headers_missing", []))
    lines.append(f"En-têtes de sécurité : {found_count} présents, {missing_count} manquants")

    return "\n".join(lines)
