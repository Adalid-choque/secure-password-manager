#!/usr/bin/env python
"""
Script de acceso rápido para la interfaz de consola del gestor de contraseñas.
Uso: python run_cli.py [--user username]
"""
import os
import sys
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'password_manager.settings')
django.setup()

from django.core.management import execute_from_command_line

if __name__ == '__main__':
    # Construir argumentos para el comando
    args = ['manage.py', 'password_manager_cli']
    
    # Agregar argumentos del usuario si existen
    if len(sys.argv) > 1:
        args.extend(sys.argv[1:])
    
    # Ejecutar comando
    execute_from_command_line(args)