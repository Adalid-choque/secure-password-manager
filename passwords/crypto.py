"""
Módulo de cifrado para el gestor de contraseñas.
Implementa cifrado simétrico AES-256 en modo CBC.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from django.conf import settings

class PasswordCrypto:
    """
    Clase para manejar el cifrado y descifrado de contraseñas usando AES-256.
    """
    
    def __init__(self):
        """Inicializa el objeto de cifrado con la clave maestra."""
        self.key = self._get_master_key()
    
    def _get_master_key(self):
        """
        Obtiene o genera la clave maestra de 32 bytes (256 bits).
        En producción, esta clave debería estar en variables de entorno.
        """
        # Por ahora usamos una clave fija para desarrollo
        # En producción, usar: os.environ.get('MASTER_KEY')
        master_key = "mi_clave_super_secreta_de_32_bytes!"
        return master_key.encode('utf-8')[:32]  # Asegurar 32 bytes
    
    def encrypt_password(self, plain_password):
        """
        Cifra una contraseña usando AES-256-CBC.
        
        Args:
            plain_password (str): Contraseña en texto plano
            
        Returns:
            str: Contraseña cifrada en base64
        """
        if not plain_password:
            return ""
        
        # Generar IV aleatorio de 16 bytes
        iv = os.urandom(16)
        
        # Crear cipher con AES-256-CBC
        cipher = Cipher(
            algorithms.AES(self.key),
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
        return base64.b64encode(encrypted_with_iv).decode('utf-8')
    
    def decrypt_password(self, encrypted_password):
        """
        Descifra una contraseña cifrada con AES-256-CBC.
        
        Args:
            encrypted_password (str): Contraseña cifrada en base64
            
        Returns:
            str: Contraseña en texto plano
        """
        if not encrypted_password:
            return ""
        
        try:
            # Decodificar de base64
            encrypted_with_iv = base64.b64decode(encrypted_password.encode('utf-8'))
            
            # Separar IV (primeros 16 bytes) y datos cifrados
            iv = encrypted_with_iv[:16]
            encrypted_data = encrypted_with_iv[16:]
            
            # Crear cipher con AES-256-CBC
            cipher = Cipher(
                algorithms.AES(self.key),
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
            
            return plain_data.decode('utf-8')
            
        except Exception as e:
            # En caso de error, retornar mensaje de error
            return f"Error al descifrar: {str(e)}"

# Instancia global para usar en las vistas
crypto = PasswordCrypto()