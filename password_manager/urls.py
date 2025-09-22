from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect
from django.contrib.auth import views as auth_views

def home_redirect(request):
    return redirect('list_passwords')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('passwords/', include('passwords.urls')),
    path('accounts/login/', auth_views.LoginView.as_view(template_name='admin/login.html'), name='login'),
    path('accounts/logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('', home_redirect, name='home'),
]