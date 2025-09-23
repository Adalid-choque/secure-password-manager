from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect

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