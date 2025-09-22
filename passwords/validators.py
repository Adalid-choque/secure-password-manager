"""
Validadores de seguridad adicionales para el gestor de contraseñas.
"""
import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class SecurityValidators:
    """
    Conjunto de validadores de seguridad para formularios y datos.
    """
    
    @staticmethod
    def validate_website_url(website):
        """
        Valida que el sitio web tenga un formato válido.
        
        Args:
            website (str): URL o nombre del sitio web
            
        Raises:
            ValidationError: Si el formato no es válido
        """
        if not website or len(website.strip()) == 0:
            raise ValidationError(_('El sitio web es obligatorio'))
        
        website = website.strip()
        
        # Verificar longitud
        if len(website) > 200:
            raise ValidationError(_('El sitio web no puede exceder 200 caracteres'))
        
        # Verificar caracteres peligrosos
        dangerous_chars = ['<', '>', '"', "'", '&', ';']
        if any(char in website for char in dangerous_chars):
            raise ValidationError(_('El sitio web contiene caracteres no permitidos'))
        
        # Si parece una URL, validar formato básico
        if '.' in website and ('http' in website.lower() or 'www' in website.lower()):
            url_pattern = re.compile(
                r'^https?://'  # http:// o https://
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # dominio
                r'localhost|'  # localhost
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
                r'(?::\d+)?'  # puerto opcional
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            
            if not url_pattern.match(website):
                raise ValidationError(_('Formato de URL inválido'))
    
    @staticmethod
    def validate_username_format(username):
        """
        Valida el formato del nombre de usuario.
        
        Args:
            username (str): Nombre de usuario
            
        Raises:
            ValidationError: Si el formato no es válido
        """
        if not username or len(username.strip()) == 0:
            raise ValidationError(_('El nombre de usuario es obligatorio'))
        
        username = username.strip()
        
        # Verificar longitud
        if len(username) > 100:
            raise ValidationError(_('El nombre de usuario no puede exceder 100 caracteres'))
        
        # Verificar caracteres peligrosos
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '\\', '/']
        if any(char in username for char in dangerous_chars):
            raise ValidationError(_('El nombre de usuario contiene caracteres no permitidos'))
        
        # Verificar que no sea solo espacios
        if username.isspace():
            raise ValidationError(_('El nombre de usuario no puede ser solo espacios'))
    
    @staticmethod
    def validate_no_sql_injection(value, field_name="campo"):
        """
        Valida que el valor no contenga patrones de inyección SQL.
        
        Args:
            value (str): Valor a validar
            field_name (str): Nombre del campo para el mensaje de error
            
        Raises:
            ValidationError: Si se detectan patrones peligrosos
        """
        if not value:
            return
        
        # Patrones comunes de inyección SQL
        sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
            r"(--|#|/\*|\*/)",
            r"(\b(OR|AND)\s+\d+\s*=\s*\d+)",
            r"(\bOR\s+\d+\s*=\s*\d+)",
            r"(\'\s*(OR|AND)\s*\'\w*\'\s*=\s*\'\w*)",
            r"(\bUNION\s+SELECT)",
        ]
        
        value_upper = value.upper()
        for pattern in sql_patterns:
            if re.search(pattern, value_upper, re.IGNORECASE):
                raise ValidationError(
                    _(f'El {field_name} contiene patrones no permitidos por seguridad')
                )
    
    @staticmethod
    def validate_no_xss_patterns(value, field_name="campo"):
        """
        Valida que el valor no contenga patrones de XSS.
        
        Args:
            value (str): Valor a validar
            field_name (str): Nombre del campo para el mensaje de error
            
        Raises:
            ValidationError: Si se detectan patrones peligrosos
        """
        if not value:
            return
        
        # Patrones comunes de XSS
        xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>",
            r"<link[^>]*>",
            r"<meta[^>]*>",
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError(
                    _(f'El {field_name} contiene código no permitido por seguridad')
                )
    
    @staticmethod
    def sanitize_input(value):
        """
        Sanitiza una entrada eliminando caracteres peligrosos.
        
        Args:
            value (str): Valor a sanitizar
            
        Returns:
            str: Valor sanitizado
        """
        if not value:
            return value
        
        # Eliminar caracteres de control
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
        
        # Escapar caracteres HTML básicos
        html_escape = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
        }
        
        for char, escape in html_escape.items():
            sanitized = sanitized.replace(char, escape)
        
        return sanitized.strip()

class RateLimitValidator:
    """
    Validador para prevenir ataques de fuerza bruta.
    """
    
    # Diccionario para rastrear intentos (en producción usar Redis/Cache)
    _attempts = {}
    
    @classmethod
    def check_rate_limit(cls, identifier, max_attempts=5, window_minutes=15):
        """
        Verifica si se ha excedido el límite de intentos.
        
        Args:
            identifier (str): Identificador único (IP, usuario, etc.)
            max_attempts (int): Máximo número de intentos
            window_minutes (int): Ventana de tiempo en minutos
            
        Returns:
            tuple: (is_allowed, attempts_remaining, reset_time)
        """
        import time
        
        current_time = time.time()
        window_seconds = window_minutes * 60
        
        if identifier not in cls._attempts:
            cls._attempts[identifier] = []
        
        # Limpiar intentos antiguos
        cls._attempts[identifier] = [
            attempt_time for attempt_time in cls._attempts[identifier]
            if current_time - attempt_time < window_seconds
        ]
        
        attempts_count = len(cls._attempts[identifier])
        
        if attempts_count >= max_attempts:
            oldest_attempt = min(cls._attempts[identifier])
            reset_time = oldest_attempt + window_seconds
            return False, 0, reset_time
        
        return True, max_attempts - attempts_count, None
    
    @classmethod
    def record_attempt(cls, identifier):
        """
        Registra un intento de acceso.
        
        Args:
            identifier (str): Identificador único
        """
        import time
        
        if identifier not in cls._attempts:
            cls._attempts[identifier] = []
        
        cls._attempts[identifier].append(time.time())
    
    @classmethod
    def reset_attempts(cls, identifier):
        """
        Resetea los intentos para un identificador.
        
        Args:
            identifier (str): Identificador único
        """
        if identifier in cls._attempts:
            del cls._attempts[identifier]