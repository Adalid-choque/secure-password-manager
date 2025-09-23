"""
Comando Django para interfaz de consola del gestor de contraseñas.
Proporciona un menú interactivo para operaciones CRUD desde terminal.
"""
import os
import sys
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.db import transaction
from passwords.models import PasswordEntry
from passwords.crypto import crypto
import getpass

class Command(BaseCommand):
    help = 'Interfaz de consola interactiva para el gestor de contraseñas'

    def __init__(self):
        super().__init__()
        self.current_user = None

    def add_arguments(self, parser):
        parser.add_argument(
            '--user',
            type=str,
            help='Nombre de usuario para autenticación',
        )

    def handle(self, *args, **options):
        """Punto de entrada principal del comando."""
        self.stdout.write(self.style.SUCCESS(' GESTOR DE CONTRASEÑAS - INTERFAZ DE CONSOLA'))
        self.stdout.write('=' * 50)
        
        # Autenticación
        if not self.authenticate_user(options.get('user')):
            return
        
        # Menú principal
        self.show_main_menu()

    def authenticate_user(self, username=None):
        """Autentica al usuario para acceder al sistema."""
        if not username:
            username = input(' Ingresa tu nombre de usuario: ')
        
        try:
            self.current_user = User.objects.get(username=username)
            password = getpass.getpass(' Ingresa tu contraseña: ')
            
            if self.current_user.check_password(password):
                self.stdout.write(
                    self.style.SUCCESS(f' Bienvenido, {self.current_user.username}!')
                )
                return True
            else:
                self.stdout.write(self.style.ERROR(' Contraseña incorrecta'))
                return False
                
        except User.DoesNotExist:
            self.stdout.write(self.style.ERROR(' Usuario no encontrado'))
            return False

    def show_main_menu(self):
        """Muestra el menú principal interactivo."""
        while True:
            self.stdout.write('\n' + '=' * 50)
            self.stdout.write(' MENÚ PRINCIPAL')
            self.stdout.write('=' * 50)
            self.stdout.write('1.  Listar todas las contraseñas')
            self.stdout.write('2.  Agregar nueva contraseña')
            self.stdout.write('3.   Ver contraseña específica')
            self.stdout.write('4.   Eliminar contraseña')
            self.stdout.write('5.  Estadísticas')
            self.stdout.write('6.  Salir')
            self.stdout.write('=' * 50)
            
            choice = input('Selecciona una opción (1-6): ').strip()
            
            if choice == '1':
                self.list_passwords()
            elif choice == '2':
                self.add_password()
            elif choice == '3':
                self.view_password()
            elif choice == '4':
                self.delete_password()
            elif choice == '5':
                self.show_statistics()
            elif choice == '6':
                self.stdout.write(self.style.SUCCESS(' ¡Hasta luego!'))
                break
            else:
                self.stdout.write(self.style.ERROR(' Opción inválida. Intenta de nuevo.'))

    def list_passwords(self):
        """Lista todas las contraseñas del usuario."""
        passwords = PasswordEntry.objects.filter(user=self.current_user).order_by('-created_at')
        
        if not passwords:
            self.stdout.write(self.style.WARNING(' No tienes contraseñas guardadas'))
            return
        
        self.stdout.write('\n TUS CONTRASEÑAS:')
        self.stdout.write('-' * 60)
        
        for i, password in enumerate(passwords, 1):
            self.stdout.write(f'{i:2d}.  {password.website:<20} |  {password.username:<15} |  {password.created_at.strftime("%d/%m/%Y")}')

    def add_password(self):
        """Agrega una nueva contraseña."""
        self.stdout.write('\n AGREGAR NUEVA CONTRASEÑA')
        self.stdout.write('-' * 30)
        
        website = input(' Sitio web: ').strip()
        if not website:
            self.stdout.write(self.style.ERROR(' El sitio web es obligatorio'))
            return
        
        username = input('👤 Usuario: ').strip()
        if not username:
            self.stdout.write(self.style.ERROR(' El usuario es obligatorio'))
            return
        
        password = getpass.getpass('🔑 Contraseña: ')
        if not password:
            self.stdout.write(self.style.ERROR(' La contraseña es obligatoria'))
            return
        
        try:
            with transaction.atomic():
                # Cifrar la contraseña
                encrypted_password = crypto.encrypt_password(password)
                
                # Crear entrada
                PasswordEntry.objects.create(
                    user=self.current_user,
                    website=website,
                    username=username,
                    encrypted_password=encrypted_password
                )
                
                self.stdout.write(self.style.SUCCESS(' Contraseña agregada y cifrada exitosamente'))
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f' Error al guardar: {str(e)}'))

    def view_password(self):
        """Muestra una contraseña específica descifrada."""
        passwords = PasswordEntry.objects.filter(user=self.current_user).order_by('-created_at')
        
        if not passwords:
            self.stdout.write(self.style.WARNING(' No tienes contraseñas guardadas'))
            return
        
        self.stdout.write('\n  SELECCIONAR CONTRASEÑA PARA VER:')
        self.stdout.write('-' * 40)
        
        for i, password in enumerate(passwords, 1):
            self.stdout.write(f'{i:2d}. {password.website} - {password.username}')
        
        try:
            choice = int(input('\nSelecciona el número: ')) - 1
            if 0 <= choice < len(passwords):
                password_entry = passwords[choice]
                decrypted = crypto.decrypt_password(password_entry.encrypted_password)
                
                self.stdout.write('\n CONTRASEÑA DESCIFRADA:')
                self.stdout.write('-' * 25)
                self.stdout.write(f' Sitio: {password_entry.website}')
                self.stdout.write(f' Usuario: {password_entry.username}')
                self.stdout.write(f' Contraseña: {decrypted}')
                self.stdout.write(f' Creada: {password_entry.created_at.strftime("%d/%m/%Y %H:%M")}')
                
            else:
                self.stdout.write(self.style.ERROR(' Número inválido'))
                
        except (ValueError, IndexError):
            self.stdout.write(self.style.ERROR(' Selección inválida'))

    def delete_password(self):
        """Elimina una contraseña."""
        passwords = PasswordEntry.objects.filter(user=self.current_user).order_by('-created_at')
        
        if not passwords:
            self.stdout.write(self.style.WARNING(' No tienes contraseñas guardadas'))
            return
        
        self.stdout.write('\n  SELECCIONAR CONTRASEÑA PARA ELIMINAR:')
        self.stdout.write('-' * 45)
        
        for i, password in enumerate(passwords, 1):
            self.stdout.write(f'{i:2d}. {password.website} - {password.username}')
        
        try:
            choice = int(input('\nSelecciona el número: ')) - 1
            if 0 <= choice < len(passwords):
                password_entry = passwords[choice]
                
                confirm = input(f'  ¿Eliminar "{password_entry.website}"? (s/N): ').lower()
                if confirm == 's':
                    password_entry.delete()
                    self.stdout.write(self.style.SUCCESS(' Contraseña eliminada exitosamente'))
                else:
                    self.stdout.write(' Eliminación cancelada')
            else:
                self.stdout.write(self.style.ERROR(' Número inválido'))
                
        except (ValueError, IndexError):
            self.stdout.write(self.style.ERROR(' Selección inválida'))

    def show_statistics(self):
        """Muestra estadísticas del usuario."""
        total = PasswordEntry.objects.filter(user=self.current_user).count()
        
        if total == 0:
            self.stdout.write(self.style.WARNING(' No hay estadísticas disponibles'))
            return
        
        recent = PasswordEntry.objects.filter(user=self.current_user).order_by('-created_at')[:5]
        
        self.stdout.write('\n ESTADÍSTICAS:')
        self.stdout.write('-' * 20)
        self.stdout.write(f' Total de contraseñas: {total}')
        self.stdout.write(f' Todas cifradas con AES-256')
        
        self.stdout.write('\n🕒 Últimas 5 contraseñas agregadas:')
        for password in recent:
            self.stdout.write(f'   • {password.website} ({password.created_at.strftime("%d/%m/%Y")})')