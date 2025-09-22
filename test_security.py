#!/usr/bin/env python
"""
Script de prueba para las mejoras de seguridad.
"""
import os
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'password_manager.settings')
django.setup()

from passwords.crypto import PasswordValidator, SecurePasswordCrypto
from passwords.validators import SecurityValidators

def test_password_validation():
    """Prueba el validador de fortaleza de contraseñas."""
    print("=== PRUEBAS DE VALIDACION DE CONTRASENAS ===\n")
    
    test_passwords = [
        "123",
        "password",
        "Password123",
        "MySecureP4ss!",
        "SuperSecureP4ssw0rd!@#"
    ]
    
    for password in test_passwords:
        is_valid, errors, score = PasswordValidator.validate_password_strength(password)
        strength = PasswordValidator.get_strength_level(score)
        
        print(f"Contrasena: '{password}'")
        print(f"  Valida: {is_valid}")
        print(f"  Fortaleza: {strength} ({score}/7)")
        if errors:
            print(f"  Errores: {', '.join(errors)}")
        print()

def test_enhanced_encryption():
    """Prueba el sistema de cifrado mejorado."""
    print("=== PRUEBAS DE CIFRADO MEJORADO ===\n")
    
    crypto = SecurePasswordCrypto()
    test_password = "MyTestP4ssw0rd!"
    
    print(f"Contrasena original: {test_password}")
    
    # Cifrar sin validación para la prueba
    encrypt_result = crypto.encrypt_password(test_password, validate_strength=False)
    print(f"Cifrado exitoso: {encrypt_result['success']}")
    
    if encrypt_result['success']:
        encrypted = encrypt_result['encrypted_password']
        print(f"Contrasena cifrada: {encrypted[:50]}...")
        
        # Descifrar
        decrypt_result = crypto.decrypt_password(encrypted)
        print(f"Descifrado exitoso: {decrypt_result['success']}")
        
        if decrypt_result['success']:
            decrypted = decrypt_result['decrypted_password']
            print(f"Contrasena descifrada: {decrypted}")
            print(f"Coincide con original: {test_password == decrypted}")
    else:
        print(f"Error en cifrado: {encrypt_result['error']}")
    
    print()

def test_security_validators():
    """Prueba los validadores de seguridad."""
    print("=== PRUEBAS DE VALIDADORES DE SEGURIDAD ===\n")
    
    # Prueba validación de sitio web
    test_websites = [
        "gmail.com",
        "https://facebook.com",
        "<script>alert('xss')</script>",
        "site'; DROP TABLE passwords; --"
    ]
    
    print("Validacion de sitios web:")
    for website in test_websites:
        try:
            SecurityValidators.validate_website_url(website)
            print(f"  OK '{website}' - Valido")
        except Exception as e:
            print(f"  ERROR '{website}' - Error: {e}")
    
    print()

if __name__ == '__main__':
    test_password_validation()
    test_enhanced_encryption()
    test_security_validators()
    print("Todas las pruebas de seguridad completadas!")