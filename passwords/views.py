from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import PasswordEntry
from .forms import PasswordEntryForm
from .crypto import crypto

@login_required
def list_passwords(request):
    """
    Vista para listar todas las contraseñas del usuario actual.
    - Filtra solo las contraseñas del usuario logueado
    - Las ordena por fecha de creación (más recientes primero)
    - Descifra las contraseñas para mostrarlas
    """
    passwords = PasswordEntry.objects.filter(user=request.user).order_by('-created_at')
    
    # Descifrar contraseñas para mostrar en la vista
    for password in passwords:
        password.decrypted_password = crypto.decrypt_password(password.encrypted_password)
    
    return render(request, 'passwords/list.html', {'passwords': passwords})

@login_required
def add_password(request):
    """
    Vista para agregar una nueva contraseña.
    - GET: Muestra el formulario vacío
    - POST: Procesa los datos, cifra la contraseña y la guarda
    """
    if request.method == 'POST':
        form = PasswordEntryForm(request.POST)
        if form.is_valid():
            password_entry = form.save(commit=False)
            password_entry.user = request.user
            
            # Cifrar la contraseña antes de guardarla
            plain_password = form.cleaned_data['password']
            password_entry.encrypted_password = crypto.encrypt_password(plain_password)
            
            password_entry.save()
            messages.success(request, 'Contraseña agregada y cifrada exitosamente.')
            return redirect('list_passwords')
    else:
        form = PasswordEntryForm()

    return render(request, 'passwords/add.html', {'form': form})

@login_required
def delete_password(request, password_id):
    """
    Vista para eliminar una contraseña específica.
    - Verifica que la contraseña pertenezca al usuario actual
    - Elimina la contraseña y redirige a la lista
    """
    password_entry = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
    password_entry.delete()
    messages.success(request, 'Contraseña eliminada exitosamente.')
    return redirect('list_passwords')