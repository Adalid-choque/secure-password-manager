from django import forms
from .models import PasswordEntry

class PasswordEntryForm(forms.ModelForm):
    """
    Formulario para crear/editar entradas de contraseñas.
    - Excluye campos automáticos (user, created_at, updated_at, encrypted_password)
    - Agrega un campo temporal 'password' para capturar la contraseña sin cifrar
    """
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'}),
        label='Contraseña',
        help_text='Será cifrada con AES-256 antes de guardarse'
    )

    class Meta:
        model = PasswordEntry
        fields = ['website', 'username']
        widgets = {
            'website': forms.TextInput(attrs={'class': 'form-control'}),
            'username': forms.TextInput(attrs={'class': 'form-control'}),
        }
        labels = {
            'website': 'Sitio Web',
            'username': 'Usuario',
        }