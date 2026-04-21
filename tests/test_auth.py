# === Tests pour le module d'authentification ===
# Vérifie l'inscription, la connexion, et la gestion des tokens JWT

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from utils.security import hash_password, verify_password, create_access_token, create_refresh_token, decode_token


class TestPasswordHashing:
    """Tests pour le hachage et la vérification des mots de passe"""

    def test_hash_password_returns_hash(self):
        """Vérifier que le hachage retourne une chaîne différente du mot de passe"""
        password = "MonMotDePasse123!"
        hashed = hash_password(password)
        assert hashed != password
        assert len(hashed) > 0

    def test_verify_correct_password(self):
        """Vérifier qu'un mot de passe correct est accepté"""
        password = "MonMotDePasse123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_verify_wrong_password(self):
        """Vérifier qu'un mot de passe incorrect est rejeté"""
        hashed = hash_password("MonMotDePasse123!")
        assert verify_password("MauvaisMotDePasse", hashed) is False

    def test_different_hashes_for_same_password(self):
        """Vérifier que deux hachages du même mot de passe sont différents (salt)"""
        password = "MonMotDePasse123!"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 != hash2  # Le salt rend chaque hash unique


class TestJWTTokens:
    """Tests pour la création et la vérification des tokens JWT"""

    def test_create_access_token(self):
        """Vérifier la création d'un token d'accès"""
        token = create_access_token("user-123", "free")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_create_refresh_token(self):
        """Vérifier la création d'un token de rafraîchissement"""
        token = create_refresh_token("user-123")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_decode_access_token(self):
        """Vérifier le décodage d'un token d'accès valide"""
        user_id = "user-123"
        role = "pro"
        token = create_access_token(user_id, role)
        payload = decode_token(token)

        assert payload["sub"] == user_id
        assert payload["role"] == role
        assert payload["type"] == "access"

    def test_decode_refresh_token(self):
        """Vérifier le décodage d'un token de rafraîchissement"""
        user_id = "user-456"
        token = create_refresh_token(user_id)
        payload = decode_token(token)

        assert payload["sub"] == user_id
        assert payload["type"] == "refresh"

    def test_decode_invalid_token_raises_error(self):
        """Vérifier qu'un token invalide lève une exception"""
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            decode_token("token-invalide-123")
        assert exc_info.value.status_code == 401


class TestUserSchemas:
    """Tests pour les schémas de validation utilisateur"""

    def test_user_create_valid(self):
        """Vérifier la validation d'une inscription correcte"""
        from schemas.user import UserCreate
        user = UserCreate(
            email="test@example.com",
            password="MotDePasse123!",
            full_name="Jean Dupont",
        )
        assert user.email == "test@example.com"
        assert user.full_name == "Jean Dupont"

    def test_user_create_invalid_email(self):
        """Vérifier le rejet d'un email invalide"""
        from schemas.user import UserCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UserCreate(email="pas-un-email", password="MotDePasse123!")

    def test_user_create_short_password(self):
        """Vérifier le rejet d'un mot de passe trop court"""
        from schemas.user import UserCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UserCreate(email="test@example.com", password="court")

    def test_user_login_valid(self):
        """Vérifier la validation d'une connexion correcte"""
        from schemas.user import UserLogin
        login = UserLogin(email="test@example.com", password="MotDePasse123!")
        assert login.email == "test@example.com"
