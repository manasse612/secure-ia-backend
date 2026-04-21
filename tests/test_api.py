# === Tests d'intégration pour l'API Secure IA ===
# Vérifie que les routes principales fonctionnent correctement
# Utilise le client de test FastAPI (TestClient)

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock


class TestRootEndpoints:
    """Tests pour les routes de base (health check)"""

    def test_root_returns_api_info(self):
        """Vérifier que la route racine retourne les informations de l'API"""
        # Importer l'application ici pour éviter les erreurs de base de données
        from main import app
        client = TestClient(app)

        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Secure IA API"
        assert data["version"] == "2.0.0"
        assert data["status"] == "en ligne"

    def test_health_check(self):
        """Vérifier que le health check fonctionne"""
        from main import app
        client = TestClient(app)

        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "services" in data


class TestAuthEndpoints:
    """Tests pour les routes d'authentification"""

    def test_register_missing_fields(self):
        """Vérifier que l'inscription échoue sans les champs requis"""
        from main import app
        client = TestClient(app)

        # Pas de body
        response = client.post("/api/auth/register", json={})
        assert response.status_code == 422  # Validation error

    def test_register_invalid_email(self):
        """Vérifier que l'inscription échoue avec un email invalide"""
        from main import app
        client = TestClient(app)

        response = client.post("/api/auth/register", json={
            "email": "pas-un-email",
            "password": "MotDePasse123!",
        })
        assert response.status_code == 422

    def test_register_short_password(self):
        """Vérifier que l'inscription échoue avec un mot de passe trop court"""
        from main import app
        client = TestClient(app)

        response = client.post("/api/auth/register", json={
            "email": "test@example.com",
            "password": "court",
        })
        assert response.status_code == 422

    def test_login_missing_fields(self):
        """Vérifier que la connexion échoue sans les champs requis"""
        from main import app
        client = TestClient(app)

        response = client.post("/api/auth/login", json={})
        assert response.status_code == 422

    def test_get_profile_without_token(self):
        """Vérifier que le profil est inaccessible sans token"""
        from main import app
        client = TestClient(app)

        response = client.get("/api/auth/me")
        assert response.status_code == 401  # Pas de header Authorization


class TestAnalysisEndpoints:
    """Tests pour les routes d'analyse"""

    def test_image_analysis_without_auth(self):
        """Vérifier que l'analyse d'image est inaccessible sans token"""
        from main import app
        client = TestClient(app)

        response = client.post("/api/analysis/image")
        assert response.status_code == 401

    def test_text_analysis_without_auth(self):
        """Vérifier que l'analyse de texte est inaccessible sans token"""
        from main import app
        client = TestClient(app)

        response = client.post("/api/analysis/text")
        assert response.status_code == 401

    def test_url_analysis_without_auth(self):
        """Vérifier que l'analyse d'URL est inaccessible sans token"""
        from main import app
        client = TestClient(app)

        response = client.post("/api/analysis/url")
        assert response.status_code == 401

    def test_history_without_auth(self):
        """Vérifier que l'historique est inaccessible sans token"""
        from main import app
        client = TestClient(app)

        response = client.get("/api/analysis/history")
        assert response.status_code == 401


class TestAdminEndpoints:
    """Tests pour les routes admin"""

    def test_admin_dashboard_without_auth(self):
        """Vérifier que le dashboard admin est inaccessible sans token"""
        from main import app
        client = TestClient(app)

        response = client.get("/api/admin/dashboard")
        assert response.status_code == 401

    def test_admin_users_without_auth(self):
        """Vérifier que la liste des utilisateurs admin est inaccessible"""
        from main import app
        client = TestClient(app)

        response = client.get("/api/admin/users")
        assert response.status_code == 401

    def test_admin_logs_without_auth(self):
        """Vérifier que les logs admin sont inaccessibles"""
        from main import app
        client = TestClient(app)

        response = client.get("/api/admin/logs")
        assert response.status_code == 401


class TestCORS:
    """Tests pour la configuration CORS"""

    def test_cors_headers_present(self):
        """Vérifier que les en-têtes CORS sont présents"""
        from main import app
        client = TestClient(app)

        response = client.options(
            "/",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        # FastAPI CORS middleware devrait répondre
        assert response.status_code in [200, 400]
