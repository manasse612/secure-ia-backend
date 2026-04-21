"""
Tests pour le client API robuste avec circuit breaker et retry.
"""

import pytest
import asyncio
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from services.api_client import (
    CircuitBreaker,
    CircuitBreakerOpen,
    with_retry,
    validate_image_file,
    validate_video_file,
    sanitize_filename,
    mask_api_key,
)


class TestCircuitBreaker:
    """Tests pour le circuit breaker."""

    @pytest.mark.asyncio
    async def test_circuit_closed_allows_calls(self):
        """Test que le circuit fermé permet les appels."""
        cb = CircuitBreaker(failure_threshold=3, name="test")
        
        mock_func = AsyncMock(return_value="success")
        result = await cb.call(mock_func, "arg1", kwarg1="value1")
        
        assert result == "success"
        assert cb.state.value == "closed"
        mock_func.assert_called_once_with("arg1", kwarg1="value1")

    @pytest.mark.asyncio
    async def test_circuit_opens_after_failures(self):
        """Test que le circuit s'ouvre après N échecs."""
        cb = CircuitBreaker(failure_threshold=3, name="test")
        
        mock_func = AsyncMock(side_effect=Exception("Erreur"))
        
        # 3 échecs pour ouvrir le circuit
        for _ in range(3):
            with pytest.raises(Exception):
                await cb.call(mock_func)
        
        # Le circuit doit être ouvert
        assert cb.state.value == "open"
        
        # Le prochain appel doit être rejeté
        with pytest.raises(CircuitBreakerOpen):
            await cb.call(mock_func)

    @pytest.mark.asyncio
    async def test_circuit_half_open_after_timeout(self):
        """Test que le circuit passe en half-open après le timeout."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1, name="test")
        
        mock_func = AsyncMock(side_effect=Exception("Erreur"))
        
        # 2 échecs pour ouvrir le circuit
        for _ in range(2):
            with pytest.raises(Exception):
                await cb.call(mock_func)
        
        assert cb.state.value == "open"
        
        # Attendre le timeout de récupération
        await asyncio.sleep(0.15)
        
        # Le prochain appel doit passer en half-open
        mock_func_success = AsyncMock(return_value="success")
        result = await cb.call(mock_func_success)
        
        assert result == "success"

    @pytest.mark.asyncio
    async def test_success_resets_circuit(self):
        """Test que le succès en half-open ferme le circuit."""
        cb = CircuitBreaker(
            failure_threshold=2,
            recovery_timeout=0.1,
            half_open_max_calls=1,
            name="test"
        )
        
        # Ouvrir le circuit
        mock_fail = AsyncMock(side_effect=Exception("Erreur"))
        for _ in range(2):
            with pytest.raises(Exception):
                await cb.call(mock_fail)
        
        assert cb.state.value == "open"
        
        # Attendre et tester le rétablissement
        await asyncio.sleep(0.15)
        
        mock_success = AsyncMock(return_value="success")
        await cb.call(mock_success)
        
        # Le circuit doit être fermé
        assert cb.state.value == "closed"


class TestRetryDecorator:
    """Tests pour le décorateur de retry."""

    @pytest.mark.asyncio
    async def test_retry_on_network_error(self):
        """Test que le retry fonctionne sur les erreurs réseau."""
        mock_func = AsyncMock(
            side_effect=[
                httpx.NetworkError("Erreur 1"),
                httpx.NetworkError("Erreur 2"),
                "success"
            ]
        )
        
        @with_retry(max_retries=3, base_delay=0.01)
        async def test_func():
            return await mock_func()
        
        result = await test_func()
        
        assert result == "success"
        assert mock_func.call_count == 3

    @pytest.mark.asyncio
    async def test_no_retry_on_success(self):
        """Test qu'il n'y a pas de retry sur le succès."""
        mock_func = AsyncMock(return_value="success")
        
        @with_retry(max_retries=3, base_delay=0.01)
        async def test_func():
            return await mock_func()
        
        result = await test_func()
        
        assert result == "success"
        assert mock_func.call_count == 1

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries(self):
        """Test qu'on abandonne après le nombre max de retries."""
        mock_func = AsyncMock(side_effect=httpx.NetworkError("Erreur"))
        
        @with_retry(max_retries=2, base_delay=0.01)
        async def test_func():
            return await mock_func()
        
        with pytest.raises(httpx.NetworkError):
            await test_func()
        
        # 1 tentative initiale + 2 retries = 3 appels
        assert mock_func.call_count == 3


class TestFileValidation:
    """Tests pour la validation des fichiers."""

    def test_validate_image_file_valid(self):
        """Test qu'une image valide passe la validation."""
        is_valid, error = validate_image_file("image/jpeg", 1024, "photo.jpg")
        assert is_valid is True
        assert error == ""

    def test_validate_image_file_invalid_type(self):
        """Test qu'un type invalide est rejeté."""
        is_valid, error = validate_image_file("application/pdf", 1024, "doc.pdf")
        assert is_valid is False
        assert "non supporté" in error

    def test_validate_image_file_too_large(self):
        """Test qu'un fichier trop grand est rejeté."""
        large_size = 15 * 1024 * 1024  # 15 Mo
        is_valid, error = validate_image_file("image/jpeg", large_size, "photo.jpg")
        assert is_valid is False
        assert "trop volumineux" in error

    def test_validate_video_file_valid(self):
        """Test qu'une vidéo valide passe la validation."""
        is_valid, error = validate_video_file("video/mp4", 1024 * 1024, "video.mp4")
        assert is_valid is True
        assert error == ""

    def test_validate_video_file_invalid_extension(self):
        """Test qu'une extension non correspondante est rejetée."""
        is_valid, error = validate_video_file("video/mp4", 1024, "video.avi")
        assert is_valid is False
        assert "non correspondante" in error


class TestSecurityUtils:
    """Tests pour les utilitaires de sécurité."""

    def test_sanitize_filename_removes_path_traversal(self):
        """Test que les tentatives de path traversal sont supprimées."""
        assert sanitize_filename("../../../etc/passwd") == "passwd"
        assert sanitize_filename("/etc/passwd") == "passwd"

    def test_sanitize_filename_removes_special_chars(self):
        """Test que les caractères spéciaux sont remplacés."""
        assert sanitize_filename("file<name>.txt") == "file_name_.txt"
        assert sanitize_filename("file:name?.jpg") == "file_name_.jpg"

    def test_sanitize_filename_limits_length(self):
        """Test que les noms de fichier trop longs sont tronqués."""
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255

    def test_mask_api_key_short(self):
        """Test le masquage d'une clé API courte."""
        assert mask_api_key("abc") == "***"

    def test_mask_api_key_long(self):
        """Test le masquage d'une clé API longue."""
        key = "sk-1234567890abcdef"
        masked = mask_api_key(key)
        assert masked.startswith("sk-1")
        assert masked.endswith("cdef")
        assert "***" in masked

    def test_mask_api_key_empty(self):
        """Test le masquage d'une clé vide."""
        assert mask_api_key("") == "Non configurée"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
