# Secure Password Manager

## Descripción General del Proyecto

Sistema gestor de contraseñas desarrollado con Django que permite crear, guardar, listar y eliminar contraseñas de forma segura. Implementa cifrado AES-256 para proteger las contraseñas almacenadas con una interfaz web intuitiva.

## Dependencias

- Python 3.8+
- Django 4.2.7
- cryptography
- SQLite (incluida con Python)

## Cómo Ejecutar la Aplicación

### Instalación

1. Clonar el repositorio:
```bash
git clone [URL_DEL_REPOSITORIO]
cd secure-password-manager
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Configurar base de datos:
```bash
python manage.py migrate
```

4. Crear usuario administrador:
```bash
python manage.py createsuperuser
```

### Ejecución

```bash
python manage.py runserver
```
Acceder a: `http://127.0.0.1:8000/`

### Funcionalidades

- **Crear contraseñas**: Formulario web con validaciones de seguridad
- **Guardar contraseñas**: Almacenamiento cifrado en base de datos
- **Listar contraseñas**: Vista de todas las contraseñas del usuario
- **Eliminar contraseñas**: Eliminación con confirmación
- **Cifrado AES-256**: Protección robusta de datos sensibles
- **Autenticación**: Sistema de usuarios integrado con Django