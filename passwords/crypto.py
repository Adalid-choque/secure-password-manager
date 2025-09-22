"""
Módulo de cifrado mejorado para el gestor de contraseñas.
Implementa cifrado simétrico AES-256 con derivación segura de claves.
"""
import os
import base64
import hashlib
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from django.conf import settings
from django.contrib.auth.models import User

class PasswordValidator:
    """
    Validador de fortaleza de contraseñas con múltiples criterios de seguridad.
    """
    
    @staticmethod
    def validate_password_strength(password):
        """
        Valida la fortaleza de una contraseña según criterios de seguridad.
        
        Args:
            password (str): Contraseña a validar
            
        Returns:
            tuple: (is_valid, errors_list, strength_score)
        """
        errors = []
        score = 0
        
        if not password:
            return False, ["La contraseña no puede estar vacía"], 0
        
        # Longitud mínima
        if len(password) < 8:
            errors.append("Debe tener al menos 8 caracteres")
        else:
            score += 1
            
        # Longitud recomendada
        if len(password) >= 12:
            score += 1
            
        # Contiene minúsculas
        if re.search(r'[a-z]', password):
            score += 1
        else:
            errors.append("Debe contener al menos una letra minúscula")
            
        # Contiene mayúsculas
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            errors.append("Debe contener al menos una letra mayúscula")
            
        # Contiene números
        if re.search(r'\d', password):
            score += 1
        else:
            errors.append("Debe contener al menos un número")
            
        # Contiene símbolos
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            errors.append("Debe contener al menos un símbolo especial")
            
        # No contiene patrones comunes
        common_patterns = ['123', 'abc', 'password', 'admin', 'qwerty']
        if not any(pattern in password.lower() for pattern in common_patterns):
            score += 1
        else:
            errors.append("No debe contener patrones comunes (123, abc, password, etc.)")
        
        is_valid = len(errors) == 0 and score >= 4
        return is_valid, errors, score

    @staticmethod
    def get_strength_level(score):
        """
        Obtiene el nivel de fortaleza basado en el puntaje.
        
        Args:
            score (int): Puntaje de fortaleza (0-7)
            
        Returns:
            str: Nivel de fortaleza
        """
        if score <= 2:
            return "Muy débil"
        elif score <= 3:
            return "Débil"
        elif score <= 4:
            return "Regular"
        elif score <= 5:
            return "Fuerte"
        else:
            return "Muy fuerte"

class SecurePasswordCrypto:
    """
    Clase mejorada para cifrado de contraseñas con derivación segura de claves.
    """
    
    def __init__(self, user=None):
        """
        Inicializa el objeto de cifrado con derivación de clave basada en usuario.
        
        Args:
            user: Usuario de Django para derivar clave personalizada
        """
        self.user = user
        self.salt = self._get_or_create_salt()
        
    def _get_or_create_salt(self):
        """
        Obtiene o crea un salt único para la derivación de claves.
        En producción, esto debería almacenarse de forma segura.
        
        Returns:
            bytes: Salt de 32 bytes
        """
        # Salt fijo para desarrollo - en producción usar almacenamiento seguro
        base_salt = "secure_password_manager_salt_2024"
        if self.user:
            # Personalizar salt por usuario
            user_salt = f"{base_salt}_{self.user.username}_{self.user.id}"
            return hashlib.sha256(user_salt.encode()).digest()
        return hashlib.sha256(base_salt.encode()).digest()
    
    def _derive_key_from_master_password(self, master_password):
        """
        Deriva una clave de cifrado segura desde la contraseña maestra usando PBKDF2.
        
        Args:
            master_password (str): Contraseña maestra del usuario
            
        Returns:
            bytes: Clave derivada de 32 bytes
        """
        # Configurar PBKDF2 con SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=self.salt,
            iterations=100000,  # 100k iteraciones para resistir ataques
            backend=default_backend()
        )
        
        # Derivar clave desde contraseña maestra
        return kdf.derive(master_password.encode('utf-8'))
    
    def _get_master_key(self):
        """
        Obtiene la clave maestra derivada de forma segura.
        En desarrollo usa clave fija, en producción debería usar contraseña del usuario.
        
        Returns:
            bytes: Clave maestra de 32 bytes
        """
        # Para desarrollo - clave fija
        master_password = "SecurePasswordManager2024!"
        
        # En producción, esto vendría de:
        # - Variable de entorno
        # - Contraseña del usuario autenticado
        # - Sistema de gestión de claves (HSM/KMS)
        
        return self._derive_key_from_master_password(master_password)
    
    def encrypt_password(self, plain_password, validate_strength=True):
        """
        Cifra una contraseña usando AES-256-CBC con validación opcional.
        
        Args:
            plain_password (str): Contraseña en texto plano
            validate_strength (bool): Si validar fortaleza de contraseña
            
        Returns:
            dict: Resultado con contraseña cifrada y metadatos
        """
        if not plain_password:
            return {
                'success': False,
                'error': 'La contraseña no puede estar vacía',
                'encrypted_password': None
            }
        
        # Validar fortaleza si está habilitado
        if validate_strength:
            is_valid, errors, score = PasswordValidator.validate_password_strength(plain_password)
            if not is_valid:
                return {
                    'success': False,
                    'error': f"Contraseña débil: {'; '.join(errors)}",
                    'encrypted_password': None,
                    'strength_errors': errors,
                    'strength_score': score
                }
        
        try:
            # Obtener clave derivada
            key = self._get_master_key()
            
            # Generar IV aleatorio de 16 bytes
            iv = os.urandom(16)
            
            # Crear cipher con AES-256-CBC
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Aplicar padding PKCS7
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plain_password.encode('utf-8'))
            padded_data += padder.finalize()
            
            # Cifrar
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combinar IV + datos cifrados y codificar en base64
            encrypted_with_iv = iv + encrypted_data
            encrypted_b64 = base64.b64encode(encrypted_with_iv).decode('utf-8')
            
            return {
                'success': True,
                'encrypted_password': encrypted_b64,
                'strength_score': PasswordValidator.validate_password_strength(plain_password)[2] if validate_strength else None
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error al cifrar: {str(e)}',
                'encrypted_password': None
            }
    
    def decrypt_password(self, encrypted_password):
        """
        Descifra una contraseña cifrada con AES-256-CBC.
        
        Args:
            encrypted_password (str): Contraseña cifrada en base64
            
        Returns:
            dict: Resultado con contraseña descifrada
        """
        if not encrypted_password:
            return {
                'success': False,
                'error': 'No hay contraseña para descifrar',
                'decrypted_password': None
            }
        
        try:
            # Obtener clave derivada
            key = self._get_master_key()
            
            # Decodificar de base64
            encrypted_with_iv = base64.b64decode(encrypted_password.encode('utf-8'))
            
            # Separar IV (primeros 16 bytes) y datos cifrados
            iv = encrypted_with_iv[:16]
            encrypted_data = encrypted_with_iv[16:]
            
            # Crear cipher con AES-256-CBC
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Descifrar
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remover padding PKCS7
            unpadder = padding.PKCS7(128).unpadder()
            plain_data = unpadder.update(padded_data)
            plain_data += unpadder.finalize()
            
            return {
                'success': True,
                'decrypted_password': plain_data.decode('utf-8')
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Error al descifrar: {str(e)}',
                'decrypted_password': None
            }

# Instancia global para compatibilidad con código existente
class LegacyCrypto:
    """Wrapper para mantener compatibilidad con la API anterior."""
    
    def __init__(self):
        self.secure_crypto = SecurePasswordCrypto()
    
    def encrypt_password(self, plain_password):
        """Cifra contraseña manteniendo API anterior."""
        result = self.secure_crypto.encrypt_password(plain_password, validate_strength=False)
        return result['encrypted_password'] if result['success'] else ""
    
    def decrypt_password(self, encrypted_password):
        """Descifra contraseña manteniendo API anterior."""
        result = self.secure_crypto.decrypt_password(encrypted_password)
        return result['decrypted_password'] if result['success'] else f"Error: {result.get('error', 'Desconocido')}"

# Instancia para compatibilidad
crypto = LegacyCrypto()

# Nueva instancia mejorada
secure_crypto = SecurePasswordCrypto()