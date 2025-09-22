from django import forms
from django.core.exceptions import ValidationError
from .models import PasswordEntry
from .validators import SecurityValidators
from .crypto import PasswordValidator

class SecurePasswordEntryForm(forms.ModelForm):
    """
    Formulario mejorado con validaciones de seguridad para entradas de contraseñas.
    """
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Mínimo 8 caracteres, incluir mayúsculas, minúsculas, números y símbolos'
        }),
        label='Contraseña',
        help_text='Será cifrada con AES-256 y derivación PBKDF2',
        min_length=8,
        max_length=128
    )
    
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirma tu contraseña'
        }),
        label='Confirmar Contraseña',
        help_text='Debe coincidir con la contraseña anterior'
    )
    
    validate_strength = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label='Validar fortaleza de contraseña',
        help_text='Verificar que la contraseña cumple criterios de seguridad'
    )

    class Meta:
        model = PasswordEntry
        fields = ['website', 'username']
        widgets = {
            'website': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'ej: gmail.com, facebook.com'
            }),
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Tu nombre de usuario o email'
            }),
        }
        labels = {
            'website': 'Sitio Web',
            'username': 'Usuario',
        }

    def clean_website(self):
        """Valida el campo website con validaciones de seguridad."""
        website = self.cleaned_data.get('website')
        
        if website:
            # Aplicar validaciones de seguridad
            SecurityValidators.validate_website_url(website)
            SecurityValidators.validate_no_sql_injection(website, 'sitio web')
            SecurityValidators.validate_no_xss_patterns(website, 'sitio web')
            
            # Sanitizar entrada
            website = SecurityValidators.sanitize_input(website)
        
        return website

    def clean_username(self):
        """Valida el campo username con validaciones de seguridad."""
        username = self.cleaned_data.get('username')
        
        if username:
            # Aplicar validaciones de seguridad
            SecurityValidators.validate_username_format(username)
            SecurityValidators.validate_no_sql_injection(username, 'nombre de usuario')
            SecurityValidators.validate_no_xss_patterns(username, 'nombre de usuario')
            
            # Sanitizar entrada
            username = SecurityValidators.sanitize_input(username)
        
        return username

    def clean_password(self):
        """Valida la fortaleza de la contraseña."""
        password = self.cleaned_data.get('password')
        validate_strength = self.cleaned_data.get('validate_strength', True)
        
        if password and validate_strength:
            is_valid, errors, score = PasswordValidator.validate_password_strength(password)
            
            if not is_valid:
                strength_level = PasswordValidator.get_strength_level(score)
                error_msg = f"Contraseña {strength_level.lower()}: {'; '.join(errors)}"
                raise ValidationError(error_msg)
        
        return password

    def clean(self):
        """Validación general del formulario."""
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        # Verificar que las contraseñas coincidan
        if password and confirm_password:
            if password != confirm_password:
                raise ValidationError({
                    'confirm_password': 'Las contraseñas no coinciden'
                })
        
        return cleaned_data

    def get_password_strength_info(self):
        """
        Obtiene información sobre la fortaleza de la contraseña.
        
        Returns:
            dict: Información de fortaleza
        """
        password = self.cleaned_data.get('password')
        if not password:
            return None
        
        is_valid, errors, score = PasswordValidator.validate_password_strength(password)
        strength_level = PasswordValidator.get_strength_level(score)
        
        return {
            'is_valid': is_valid,
            'errors': errors,
            'score': score,
            'max_score': 7,
            'strength_level': strength_level,
            'percentage': int((score / 7) * 100)
        }

# Mantener formulario original para compatibilidad
class PasswordEntryForm(forms.ModelForm):
    """
    Formulario original para compatibilidad con código existente.
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