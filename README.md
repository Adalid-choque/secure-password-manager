# Secure Password Manager

Un gestor de contraseñas seguro desarrollado con Django y SQLite.

## Descripción

Este proyecto implementa un sistema de gestión de contraseñas con cifrado seguro, desarrollado como parte del curso de Fundamentos de Ciberseguridad.

## Tecnologías

- Python 3.x
- Django 4.2.7
- SQLite
- Cryptography

## Instalación

1. Clonar el repositorio
2. Instalar dependencias: `pip install -r requirements.txt`
3. Ejecutar migraciones: `python manage.py migrate`
4. Crear superusuario: `python manage.py createsuperuser`

## Uso

### 🌐 Interfaz Web
```bash
python manage.py runserver
```
Acceder a: `http://127.0.0.1:8000/`

### 🖥️ Interfaz de Consola
```bash
python manage.py password_manager_cli
# o
python run_cli.py
```

## Funcionalidades

### ✅ Implementadas
- **CRUD de contraseñas**: Crear, listar, eliminar contraseñas
- **Cifrado AES-256**: Todas las contraseñas están cifradas
- **Interfaz web**: Bootstrap con autenticación
- **Interfaz de consola**: Menú interactivo desde terminal
- **Autenticación**: Sistema de usuarios de Django

### 🔐 Seguridad
- Cifrado simétrico AES-256-CBC
- Vector de inicialización único por contraseña
- Padding PKCS7 estándar
- Codificación Base64 para almacenamiento

## Estado del Proyecto

🚀 **Fase 5 completada** - Interfaz de consola implementada

## Funcionalidades

### ✅ Implementadas
- **CRUD de contraseñas**: Crear, listar, eliminar contraseñas
- **Cifrado AES-256**: Todas las contraseñas están cifradas
- **Interfaz web**: Bootstrap con autenticación
- **Interfaz de consola**: Menú interactivo desde terminal
- **Autenticación**: Sistema de usuarios de Django
- **Validación de fortaleza**: Criterios de seguridad para contraseñas
- **Rate limiting**: Protección contra ataques de fuerza bruta

### 🔐 Seguridad Avanzada
- **Derivación PBKDF2**: 100,000 iteraciones con salt único
- **Validación de entrada**: Protección contra SQL injection y XSS
- **Fortaleza de contraseñas**: 7 criterios de validación
- **Rate limiting**: Límites por IP y usuario
- **Cifrado mejorado**: AES-256-CBC con derivación segura de claves
- **Auto-ocultado**: Contraseñas se ocultan automáticamente por seguridad

### 🧪 Pruebas
```bash
python test_security.py
```

## Estado del Proyecto

🚀 **Fase 6 completada** - Mejoras de seguridad implementadas