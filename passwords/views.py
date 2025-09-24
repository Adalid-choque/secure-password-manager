from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from .models import PasswordEntry
from .forms import PasswordEntryForm, SecurePasswordEntryForm
from .crypto import crypto, SecurePasswordCrypto
from .validators import RateLimitValidator
import json

def get_client_ip(request):
    """Obtiene la IP del cliente para rate limiting."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

@login_required
def list_passwords(request):
    """
    Vista para listar todas las contraseñas del usuario actual.
    - Filtra solo las contraseñas del usuario logueado
    - Las ordena por fecha de creación (más recientes primero)
    - Descifra las contraseñas usando ambos sistemas para compatibilidad
    """
    passwords = PasswordEntry.objects.filter(user=request.user).order_by('-created_at')
    
    # Descifrar contraseñas para mostrar en la vista
    for password in passwords:
        # Intentar primero con el sistema original (para compatibilidad)
        try:
            decrypted = crypto.decrypt_password(password.encrypted_password)
            if not decrypted.startswith("Error"):
                password.decrypted_password = decrypted
            else:
                raise Exception("Sistema original falló")
        except:
            # Si falla, intentar con el sistema mejorado
            try:
                secure_crypto = SecurePasswordCrypto(user=request.user)
                decrypt_result = secure_crypto.decrypt_password(password.encrypted_password)
                if decrypt_result['success']:
                    password.decrypted_password = decrypt_result['decrypted_password']
                else:
                    password.decrypted_password = f"Error: {decrypt_result['error']}"
            except:
                password.decrypted_password = "Error: No se pudo descifrar"
    
    return render(request, 'passwords/list.html', {'passwords': passwords})

@login_required
def add_password(request):
    """
    Vista mejorada para agregar una nueva contraseña con validaciones de seguridad.
    - GET: Muestra el formulario con validaciones
    - POST: Procesa los datos con cifrado mejorado y validaciones
    """
    # Verificar rate limiting
    client_ip = get_client_ip(request)
    identifier = f"{request.user.id}_{client_ip}"
    
    if request.method == 'POST':
        # Verificar límite de intentos
        is_allowed, remaining, reset_time = RateLimitValidator.check_rate_limit(
            identifier, max_attempts=10, window_minutes=5
        )
        
        if not is_allowed:
            messages.error(request, 
                f'Demasiados intentos. Intenta de nuevo en unos minutos.')
            return render(request, 'passwords/add.html', {'form': SecurePasswordEntryForm()})
        
        # Registrar intento
        RateLimitValidator.record_attempt(identifier)
        
        form = SecurePasswordEntryForm(request.POST)
        if form.is_valid():
            password_entry = form.save(commit=False)
            password_entry.user = request.user
            
            # Usar cifrado mejorado
            secure_crypto = SecurePasswordCrypto(user=request.user)
            plain_password = form.cleaned_data['password']
            validate_strength = form.cleaned_data.get('validate_strength', True)
            
            encrypt_result = secure_crypto.encrypt_password(
                plain_password, 
                validate_strength=validate_strength
            )
            
            if encrypt_result['success']:
                password_entry.encrypted_password = encrypt_result['encrypted_password']
                password_entry.save()
                
                # Resetear intentos en caso de éxito
                RateLimitValidator.reset_attempts(identifier)
                
                # Mensaje con información de fortaleza
                strength_info = form.get_password_strength_info()
                if strength_info:
                    strength_msg = f" (Fortaleza: {strength_info['strength_level']})"
                else:
                    strength_msg = ""
                
                messages.success(request, 
                    f'Contraseña agregada y cifrada exitosamente{strength_msg}.')
                return redirect('list_passwords')
            else:
                messages.error(request, f'Error al cifrar: {encrypt_result["error"]}')
        else:
            # Mostrar errores de validación
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = SecurePasswordEntryForm()

    return render(request, 'passwords/add.html', {'form': form})

@login_required
def add_password_simple(request):
    """
    Vista simple para compatibilidad con el formulario original.
    """
    if request.method == 'POST':
        form = PasswordEntryForm(request.POST)
        if form.is_valid():
            password_entry = form.save(commit=False)
            password_entry.user = request.user
            
            # Cifrar la contraseña antes de guardarla (método original)
            plain_password = form.cleaned_data['password']
            password_entry.encrypted_password = crypto.encrypt_password(plain_password)
            
            password_entry.save()
            messages.success(request, 'Contraseña agregada y cifrada exitosamente.')
            return redirect('list_passwords')
    else:
        form = PasswordEntryForm()

    return render(request, 'passwords/add_simple.html', {'form': form})

@login_required
@require_http_methods(["POST"])
def delete_password(request, password_id):
    """
    Vista mejorada para eliminar una contraseña específica.
    - Solo acepta POST para prevenir CSRF
    - Verifica que la contraseña pertenezca al usuario actual
    - Incluye rate limiting para prevenir abuso
    """
    # Verificar rate limiting
    client_ip = get_client_ip(request)
    identifier = f"delete_{request.user.id}_{client_ip}"
    
    is_allowed, remaining, reset_time = RateLimitValidator.check_rate_limit(
        identifier, max_attempts=20, window_minutes=5
    )
    
    if not is_allowed:
        messages.error(request, 'Demasiadas eliminaciones. Intenta de nuevo en unos minutos.')
        return redirect('list_passwords')
    
    # Registrar intento
    RateLimitValidator.record_attempt(identifier)
    
    password_entry = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
    website_name = password_entry.website  # Guardar para el mensaje
    password_entry.delete()
    
    messages.success(request, f'Contraseña de "{website_name}" eliminada exitosamente.')
    return redirect('list_passwords')

@login_required
def check_password_strength(request):
    """
    API endpoint para verificar fortaleza de contraseña en tiempo real.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            password = data.get('password', '')
            
            from .crypto import PasswordValidator
            is_valid, errors, score = PasswordValidator.validate_password_strength(password)
            strength_level = PasswordValidator.get_strength_level(score)
            
            return JsonResponse({
                'is_valid': is_valid,
                'errors': errors,
                'score': score,
                'max_score': 7,
                'strength_level': strength_level,
                'percentage': int((score / 7) * 100)
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    
    return JsonResponse({'error': 'Método no permitido'}, status=405)

def custom_login(request):
    """
    Vista personalizada de login que no usa el template base.
    """
    if request.user.is_authenticated:
        return redirect('list_passwords')
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('list_passwords')
    else:
        form = AuthenticationForm()
    
    return render(request, 'passwords/login.html', {'form': form})