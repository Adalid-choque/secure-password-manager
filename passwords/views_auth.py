from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, update_session_auth_hash
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from .forms import CustomPasswordChangeForm

@never_cache
@csrf_protect
def custom_login_view(request):
    if request.user.is_authenticated:
        return redirect('/passwords/')
    
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('/passwords/')
    else:
        form = AuthenticationForm()
    
    return render(request, 'passwords/login.html', {'form': form})

@login_required
def change_password(request):
    if request.method == 'POST':
        form = CustomPasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Tu contraseña ha sido cambiada exitosamente.')
            return redirect('list_passwords')
    else:
        form = CustomPasswordChangeForm(request.user)
    
    return render(request, 'passwords/change_password.html', {'form': form})