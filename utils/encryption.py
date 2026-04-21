# === Utilitaires de chiffrement ===
# Chiffrement AES-256-GCM pour les données sensibles (résultats d'analyse)
# Les données sont chiffrées avant stockage en base et déchiffrées à la lecture

import os
import json
import base64
from typing import Optional, Dict, Any, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# --- Configuration du chiffrement ---
# La clé doit être stockée dans une variable d'environnement sécurisée
# En production, utiliser un HSM ou un vault (HashiCorp Vault, AWS KMS, etc.)
_ENCRYPTION_KEY: Optional[bytes] = None


def _get_encryption_key() -> bytes:
    """
    Obtenir la clé de chiffrement depuis les variables d'environnement.
    La clé doit être une chaîne base64 de 32 bytes (256 bits).
    """
    global _ENCRYPTION_KEY
    
    if _ENCRYPTION_KEY is not None:
        return _ENCRYPTION_KEY
    
    key_b64 = os.environ.get("ENCRYPTION_KEY")
    if not key_b64:
        # Clé de développement (à ne PAS utiliser en production!)
        # Générer une clé aléatoire unique à chaque démarrage en dev
        import warnings
        import secrets
        warnings.warn(
            "ENCRYPTION_KEY non définie! Génération d'une clé de développement temporaire. "
            "NE PAS UTILISER EN PRODUCTION! Les données chiffrées ne seront pas lisibles après redémarrage."
        )
        # Générer une clé aléatoire de 32 bytes pour ce session uniquement
        _ENCRYPTION_KEY = secrets.token_bytes(32)
        return _ENCRYPTION_KEY
    
    # Décoder la clé base64
    try:
        _ENCRYPTION_KEY = base64.b64decode(key_b64)
        if len(_ENCRYPTION_KEY) != 32:
            raise ValueError("La clé de chiffrement doit faire exactement 32 bytes (256 bits)")
        return _ENCRYPTION_KEY
    except Exception as e:
        raise ValueError(f"Clé de chiffrement invalide: {e}")


def encrypt_sensitive_data(data: Union[str, Dict, bytes]) -> str:
    """
    Chiffrer des données sensibles avant stockage en base.
    
    Args:
        data: Données à chiffrer (string, dict, ou bytes)
    
    Returns:
        Chaîne base64 contenant: nonce + ciphertext + tag
    """
    # Normaliser les données en bytes
    if isinstance(data, dict):
        plaintext = json.dumps(data, ensure_ascii=False).encode('utf-8')
    elif isinstance(data, str):
        plaintext = data.encode('utf-8')
    elif isinstance(data, bytes):
        plaintext = data
    else:
        raise TypeError("Les données doivent être str, dict ou bytes")
    
    # Obtenir la clé
    key = _get_encryption_key()
    
    # Générer un nonce aléatoire (96 bits pour AES-GCM)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    # Chiffrer les données
    # AES-GCM retourne ciphertext + tag (128 bits) concaténés
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Combiner nonce + ciphertext et encoder en base64
    encrypted = base64.b64encode(nonce + ciphertext).decode('utf-8')
    
    return encrypted


def decrypt_sensitive_data(encrypted_data: str) -> Union[str, Dict]:
    """
    Déchiffrer des données sensibles après récupération de la base.
    
    Args:
        encrypted_data: Chaîne base64 contenant nonce + ciphertext + tag
    
    Returns:
        Données déchiffrées (string ou dict)
    """
    if not encrypted_data:
        return ""
    
    try:
        # Décoder le base64
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extraire le nonce (12 premiers bytes)
        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]
        
        # Obtenir la clé
        key = _get_encryption_key()
        
        # Déchiffrer
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Décoder en UTF-8
        result = plaintext.decode('utf-8')
        
        # Essayer de parser comme JSON
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return result
            
    except Exception as e:
        # En cas d'erreur, retourner une indication de données corrompues
        raise ValueError(f"Impossible de déchiffrer les données: {e}")


def mask_sensitive_fields(data: Dict[str, Any], fields: list) -> Dict[str, Any]:
    """
    Masquer certains champs sensibles dans un dictionnaire.
    Utile pour le logging ou les réponses API.
    
    Args:
        data: Dictionnaire contenant les données
        fields: Liste des champs à masquer
    
    Returns:
        Copie du dictionnaire avec les champs masqués
    """
    result = data.copy()
    for field in fields:
        if field in result and result[field]:
            value = str(result[field])
            if len(value) > 8:
                result[field] = value[:4] + "****" + value[-4:]
            else:
                result[field] = "****"
    return result


# --- Helper pour SQLAlchemy ---
class EncryptedString:
    """
    Type SQLAlchemy pour stocker des chaînes chiffrées.
    Usage:
        from sqlalchemy import Column, String
        from utils.encryption import EncryptedString
        
        result_encrypted = Column(String(4000))  # Stocké chiffré
        
        @property
        def result(self):
            return EncryptedString.decrypt(self.result_encrypted)
        
        @result.setter
        def result(self, value):
            self.result_encrypted = EncryptedString.encrypt(value)
    """
    
    @staticmethod
    def encrypt(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return encrypt_sensitive_data(value)
    
    @staticmethod
    def decrypt(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        try:
            result = decrypt_sensitive_data(value)
            if isinstance(result, dict):
                return json.dumps(result)
            return result
        except ValueError:
            # Si le déchiffrement échoue, retourner la valeur brute
            # (peut-être non chiffrée pour la rétrocompatibilité)
            return value
