from django.urls import path
from . import views

urlpatterns = [
    path('', views.list_passwords, name='list_passwords'),
    path('add/', views.add_password, name='add_password'),
    path('delete/<int:password_id>/', views.delete_password, name='delete_password'),
]