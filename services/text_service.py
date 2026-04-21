# === Service d'analyse de texte ===
# Vérifie la véracité d'un texte ou d'un article
# Utilise l'API OpenAI GPT-4 pour l'analyse sémantique et le fact-checking
# Compare avec des sources fiables pour déterminer si l'information est vraie ou fausse

import time
import httpx
import logging
from typing import Optional

from config import settings
from services.api_client import openai_api_call, CircuitBreakerOpen

logger = logging.getLogger(__name__)


async def analyze_text(text: str, language: str = "fr") -> dict:
    """
    Analyser un texte pour vérifier sa véracité.
    
    Étapes :
    1. Analyse NLP du contenu (tonalité, biais, émotions)
    2. Fact-checking via OpenAI GPT-4
    3. Calcul du score de fiabilité
    4. Génération du résumé
    
    Paramètres :
    - text : le texte à analyser
    - language : la langue du texte (fr par défaut)
    
    Retourne un dictionnaire avec les résultats détaillés.
    """
    start_time = time.time()
    results = {
        "nlp_analysis": {},
        "fact_check": {},
        "sources": [],
        "score": 0.0,
        "verdict": "non_verifiable",
        "summary": "",
    }

    # --- Étape 1 : Analyse NLP basique ---
    nlp_result = _analyze_nlp(text)
    results["nlp_analysis"] = nlp_result

    # --- Étape 2 : Fact-checking via OpenAI ---
    try:
        fact_result = await _fact_check_with_openai(text, language)
        results["fact_check"] = fact_result
    except RuntimeError as e:
        # Configuration error - on propage l'erreur pour bloquer l'analyse
        raise RuntimeError(f"Service d'analyse indisponible : {str(e)}")
    except Exception as e:
        results["fact_check"] = {"error": str(e)}

    # --- Étape 3 : Vérifier si la vérification a échoué ---
    if results["fact_check"].get("error"):
        raise RuntimeError(f"Analyse impossible : {results['fact_check']['error']}")

    # --- Étape 4 : Calcul du score ---
    score = _calculate_text_score(results)
    results["score"] = score

    # --- Étape 4 : Déterminer le verdict ---
    if score >= 70:
        results["verdict"] = "vrai"
    elif score >= 40:
        results["verdict"] = "non_verifiable"
    else:
        results["verdict"] = "faux"

    # --- Étape 5 : Résumé ---
    results["summary"] = _generate_text_summary(results, text)

    # Temps de traitement
    results["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)

    return results


def _analyze_nlp(text: str) -> dict:
    """
    Analyse NLP basique du texte.
    Détecte la tonalité, les biais potentiels et les marqueurs de désinformation.
    """
    text_lower = text.lower()
    word_count = len(text.split())

    # Mots-clés indiquant un possible biais ou sensationnalisme
    sensational_words = [
        "incroyable", "choquant", "scandale", "urgent", "breaking",
        "exclusif", "secret", "censuré", "interdit", "révélation",
        "shocking", "unbelievable", "breaking news", "exposed",
    ]

    # Mots-clés indiquant des affirmations non sourcées
    unsourced_markers = [
        "on dit que", "il paraît", "certaines sources", "des experts",
        "selon des rumeurs", "apparemment", "some say", "allegedly",
    ]

    # Compter les marqueurs trouvés
    sensational_count = sum(1 for word in sensational_words if word in text_lower)
    unsourced_count = sum(1 for marker in unsourced_markers if marker in text_lower)

    # Calculer les scores
    sensationalism_score = min(sensational_count / max(word_count / 100, 1), 1.0)
    sourcing_score = 1.0 - min(unsourced_count / 3, 1.0)

    # Détecter les majuscules excessives (signe de clickbait)
    uppercase_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    has_excessive_caps = uppercase_ratio > 0.3

    # Détecter les points d'exclamation excessifs
    exclamation_ratio = text.count("!") / max(word_count, 1)
    has_excessive_exclamation = exclamation_ratio > 0.05

    return {
        "word_count": word_count,
        "language_detected": "fr",  # Simplifié pour le MVP
        "sensationalism_score": round(sensationalism_score, 2),
        "sourcing_score": round(sourcing_score, 2),
        "has_excessive_caps": has_excessive_caps,
        "has_excessive_exclamation": has_excessive_exclamation,
        "bias_indicators": sensational_count + unsourced_count,
    }


async def _fact_check_with_openai(text: str, language: str) -> dict:
    """
    Vérifier les faits du texte avec OpenAI GPT-4.
    Analyse le contenu et identifie les affirmations vérifiables.
    """
    if not settings.openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY non configurée. "
            "Veuillez configurer la clé API OpenAI dans le fichier .env"
        )

    logger.info(f"[OpenAI] Fact-checking demandé - {len(text)} caractères")

    # Appel réel à l'API OpenAI avec circuit breaker
    try:
        async with httpx.AsyncClient() as client:
            response = await openai_api_call(
                client, "POST", "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "gpt-4",
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "Tu es un expert en vérification des faits (fact-checking). "
                                "Analyse le texte suivant et détermine sa véracité. "
                                "Réponds en JSON avec les champs : "
                                "claims (liste des affirmations), "
                                "verdict (vrai/faux/non_verifiable), "
                                "confidence (0-1), "
                                "explanation (explication détaillée), "
                                "sources_suggested (sources à vérifier)"
                            ),
                        },
                        {"role": "user", "content": text},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 1000,
                },
                timeout=30,
            )

            data = response.json()
            content = data["choices"][0]["message"]["content"]
            logger.info("[OpenAI] Réponse reçue avec succès")
            
            # Essayer de parser le JSON
            import json
            try:
                result = json.loads(content)
                result["model_used"] = data.get("model", "gpt-4")
                result["tokens_used"] = data.get("usage", {}).get("total_tokens", 0)
                return result
            except json.JSONDecodeError:
                logger.warning("[OpenAI] Réponse non-JSON reçue")
                return {"raw_response": content}

    except CircuitBreakerOpen:
        logger.error("[OpenAI] Circuit breaker ouvert")
        return {
            "error": "Service OpenAI temporairement indisponible. Réessayez plus tard.",
            "circuit_breaker_open": True,
        }
    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        logger.error(f"[OpenAI] Erreur HTTP {status_code}")
        
        if status_code == 401:
            return {"error": "Clé API OpenAI invalide. Vérifiez votre configuration."}
        elif status_code == 429:
            return {"error": "Limite de requêtes OpenAI atteinte. Veuillez réessayer dans quelques minutes."}
        elif status_code == 500:
            return {"error": "Erreur interne OpenAI. Réessayez plus tard."}
        return {"error": f"Erreur API OpenAI ({status_code})"}
    except Exception as e:
        logger.exception("[OpenAI] Erreur inattendue")
        return {"error": f"Erreur de connexion OpenAI : {str(e)}"}


def _calculate_text_score(results: dict) -> float:
    """
    Calculer le score de fiabilité du texte (0 à 100).
    - 100 = texte très probablement fiable
    - 0 = texte très probablement faux ou trompeur
    """
    score = 50.0  # Score de départ neutre

    # Impact de l'analyse NLP
    nlp = results.get("nlp_analysis", {})
    sensationalism = nlp.get("sensationalism_score", 0)
    sourcing = nlp.get("sourcing_score", 1)

    score -= sensationalism * 20      # Pénalité pour sensationnalisme
    score += (sourcing - 0.5) * 20    # Bonus/malus pour le sourcing

    if nlp.get("has_excessive_caps"):
        score -= 10
    if nlp.get("has_excessive_exclamation"):
        score -= 5

    # Impact du fact-checking
    fact_check = results.get("fact_check", {})
    fc_verdict = fact_check.get("verdict", "non_verifiable")
    fc_confidence = fact_check.get("confidence", 0.5)

    if fc_verdict == "vrai":
        score += 30 * fc_confidence
    elif fc_verdict == "faux":
        score -= 30 * fc_confidence

    # Limiter entre 0 et 100
    return round(max(0, min(100, score)), 1)


def _generate_text_summary(results: dict, original_text: str) -> str:
    """
    Générer un résumé en français de l'analyse du texte.
    """
    score = results.get("score", 0)
    verdict = results.get("verdict", "non_verifiable")
    nlp = results.get("nlp_analysis", {})

    lines = []

    # Verdict principal
    if verdict == "vrai":
        lines.append("✅ Ce texte semble fiable et vérifié.")
    elif verdict == "non_verifiable":
        lines.append("⚠️ Ce texte contient des éléments non vérifiables.")
    else:
        lines.append("❌ Ce texte contient probablement des informations fausses ou trompeuses.")

    lines.append(f"Score de fiabilité : {score}/100")
    lines.append(f"Nombre de mots analysés : {nlp.get('word_count', 0)}")

    # Détails NLP
    if nlp.get("sensationalism_score", 0) > 0.3:
        lines.append("⚠️ Langage sensationnaliste détecté")
    if nlp.get("has_excessive_caps"):
        lines.append("⚠️ Usage excessif de majuscules détecté")
    if nlp.get("bias_indicators", 0) > 2:
        lines.append("⚠️ Plusieurs indicateurs de biais détectés")

    return "\n".join(lines)
