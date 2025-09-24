from django.urls import path
from . import views
from .views_auth import change_password

urlpatterns = [
    path('', views.list_passwords, name='list_passwords'),
    path('add/', views.add_password, name='add_password'),
    path('add/simple/', views.add_password_simple, name='add_password_simple'),
    path('delete/<int:password_id>/', views.delete_password, name='delete_password'),
    path('api/check-password-strength/', views.check_password_strength, name='check_password_strength'),
    path('change-password/', change_password, name='change_password'),
]