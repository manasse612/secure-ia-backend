# === Tests pour les modules d'analyse ===
# Vérifie le fonctionnement des services d'analyse image, texte et URL

import pytest
from services.text_service import _analyze_nlp, _calculate_text_score, _simulate_fact_check
from services.url_service import _parse_url, _simulate_virustotal_scan, _calculate_url_score


class TestImageAnalysis:
    """Tests pour le service d'analyse d'images"""

    def test_simulate_ai_detection_returns_dict(self):
        """Vérifier que la simulation retourne un dictionnaire valide"""
        from services.image_service import _simulate_ai_detection
        result = _simulate_ai_detection()
        assert isinstance(result, dict)
        assert "ai_generated_probability" in result
        assert "mode" in result
        assert result["mode"] == "simulation"

    def test_ai_probability_range(self):
        """Vérifier que la probabilité IA est entre 0 et 1"""
        from services.image_service import _simulate_ai_detection
        for _ in range(10):
            result = _simulate_ai_detection()
            prob = result["ai_generated_probability"]
            assert 0 <= prob <= 1

    def test_authenticity_score_calculation(self):
        """Vérifier le calcul du score d'authenticité"""
        from services.image_service import _calculate_authenticity_score

        # Image avec haute probabilité IA = score bas
        results_fake = {
            "ai_detection": {"ai_generated_probability": 0.9},
            "metadata": {"has_exif": False},
        }
        score_fake = _calculate_authenticity_score(results_fake)
        assert score_fake < 50

        # Image avec faible probabilité IA + EXIF = score haut
        results_real = {
            "ai_detection": {"ai_generated_probability": 0.1},
            "metadata": {"has_exif": True, "software": None},
        }
        score_real = _calculate_authenticity_score(results_real)
        assert score_real > 50

    def test_score_bounds(self):
        """Vérifier que le score est toujours entre 0 et 100"""
        from services.image_service import _calculate_authenticity_score

        # Cas extrême : très haute probabilité IA
        results = {
            "ai_detection": {"ai_generated_probability": 1.0},
            "metadata": {"has_exif": False, "software": "Photoshop"},
        }
        score = _calculate_authenticity_score(results)
        assert 0 <= score <= 100

    def test_generate_summary_authentic(self):
        """Vérifier le résumé pour une image authentique"""
        from services.image_service import _generate_summary
        results = {
            "score": 85,
            "verdict": "authentique",
            "ai_detection": {"ai_generated_probability": 0.1},
            "metadata": {"has_exif": True, "camera": "Canon EOS R5"},
        }
        summary = _generate_summary(results)
        assert "authentique" in summary.lower() or "✅" in summary
        assert "85/100" in summary


class TestTextAnalysis:
    """Tests pour le service d'analyse de texte"""

    def test_nlp_analysis_normal_text(self):
        """Vérifier l'analyse NLP d'un texte normal"""
        text = "Le président a annoncé une nouvelle politique économique lors de la conférence de presse."
        result = _analyze_nlp(text)
        assert isinstance(result, dict)
        assert "word_count" in result
        assert result["word_count"] > 0
        assert result["sensationalism_score"] == 0  # Pas de mots sensationnalistes

    def test_nlp_analysis_sensational_text(self):
        """Vérifier la détection du sensationnalisme"""
        text = "INCROYABLE ! SCANDALE CHOQUANT ! RÉVÉLATION EXCLUSIVE !!!!"
        result = _analyze_nlp(text)
        assert result["sensationalism_score"] > 0
        assert result["has_excessive_caps"] is True
        assert result["has_excessive_exclamation"] is True

    def test_nlp_analysis_unsourced_text(self):
        """Vérifier la détection des sources manquantes"""
        text = "Selon des rumeurs, il paraît que certaines sources affirment que on dit que cela est vrai."
        result = _analyze_nlp(text)
        assert result["sourcing_score"] < 1.0
        assert result["bias_indicators"] > 0

    def test_simulate_fact_check(self):
        """Vérifier la simulation de fact-checking"""
        result = _simulate_fact_check("Un texte quelconque pour tester.")
        assert isinstance(result, dict)
        assert "mode" in result
        assert result["mode"] == "simulation"
        assert "verdict" in result
        assert result["verdict"] in ["vrai", "faux", "non_verifiable"]

    def test_text_score_calculation(self):
        """Vérifier le calcul du score de fiabilité"""
        # Texte fiable
        results_good = {
            "nlp_analysis": {
                "sensationalism_score": 0,
                "sourcing_score": 1.0,
                "has_excessive_caps": False,
                "has_excessive_exclamation": False,
            },
            "fact_check": {"verdict": "vrai", "confidence": 0.8},
        }
        score_good = _calculate_text_score(results_good)
        assert score_good > 50

        # Texte suspect
        results_bad = {
            "nlp_analysis": {
                "sensationalism_score": 0.8,
                "sourcing_score": 0.2,
                "has_excessive_caps": True,
                "has_excessive_exclamation": True,
            },
            "fact_check": {"verdict": "faux", "confidence": 0.9},
        }
        score_bad = _calculate_text_score(results_bad)
        assert score_bad < 50


class TestUrlAnalysis:
    """Tests pour le service d'analyse d'URL"""

    def test_parse_valid_url(self):
        """Vérifier le parsing d'une URL valide"""
        result = _parse_url("https://www.example.com/page")
        assert result["hostname"] == "www.example.com"
        assert result["scheme"] == "https"
        assert result["is_https"] is True

    def test_parse_url_without_protocol(self):
        """Vérifier l'ajout automatique de https://"""
        result = _parse_url("www.example.com")
        assert result["scheme"] == "https"
        assert result["hostname"] == "www.example.com"

    def test_parse_http_url(self):
        """Vérifier le parsing d'une URL HTTP (non sécurisée)"""
        result = _parse_url("http://example.com")
        assert result["is_https"] is False

    def test_simulate_virustotal(self):
        """Vérifier la simulation VirusTotal"""
        result = _simulate_virustotal_scan("https://example.com")
        assert isinstance(result, dict)
        assert "malicious" in result
        assert "harmless" in result
        assert result["mode"] == "simulation"

    def test_url_score_with_ssl(self):
        """Vérifier le score avec SSL valide"""
        results = {
            "url_info": {"is_https": True},
            "ssl_check": {"has_ssl": True, "valid": True},
            "virustotal": {"malicious": 0, "suspicious": 0},
            "security_headers": {"score": 80},
        }
        score = _calculate_url_score(results)
        assert score > 60

    def test_url_score_without_ssl(self):
        """Vérifier le score sans SSL"""
        results = {
            "url_info": {"is_https": False},
            "ssl_check": {"has_ssl": False},
            "virustotal": {"malicious": 0, "suspicious": 0},
            "security_headers": {"score": 0},
        }
        score = _calculate_url_score(results)
        assert score < 50

    def test_url_score_malicious(self):
        """Vérifier le score avec détections malveillantes"""
        results = {
            "url_info": {"is_https": True},
            "ssl_check": {"has_ssl": True, "valid": True},
            "virustotal": {"malicious": 5, "suspicious": 3},
            "security_headers": {"score": 50},
        }
        score = _calculate_url_score(results)
        assert score < 30  # Fortement pénalisé


class TestRateLimiter:
    """Tests pour le limiteur de débit"""

    def test_quota_values(self):
        """Vérifier les valeurs de quota par plan"""
        # Les quotas sont gérés via config_helper.get_plan_quotas()
        from services.config_helper import get_plan_quotas
        import asyncio
        
        quotas = asyncio.run(get_plan_quotas())
        assert quotas["free"] == 10
        assert quotas["pro"] == 500
        assert quotas["business"] == 5000
        assert quotas["admin"] == 99999
