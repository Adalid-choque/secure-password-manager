# 🖥️ Interfaz de Consola - Gestor de Contraseñas

## 🚀 Cómo usar la interfaz de consola

### **Método 1: Comando Django**
```bash
python manage.py password_manager_cli
```

### **Método 2: Script directo**
```bash
python run_cli.py
```

### **Con usuario específico:**
```bash
python manage.py password_manager_cli --user tu_usuario
python run_cli.py --user tu_usuario
```

## 📋 Funcionalidades disponibles

### **1. 📋 Listar contraseñas**
- Muestra todas las contraseñas del usuario
- Formato: Sitio web | Usuario | Fecha de creación

### **2. ➕ Agregar contraseña**
- Solicita: sitio web, usuario y contraseña
- Cifra automáticamente con AES-256
- Confirmación de guardado exitoso

### **3. 👁️ Ver contraseña**
- Lista numerada de contraseñas
- Selección por número
- Muestra contraseña descifrada temporalmente

### **4. 🗑️ Eliminar contraseña**
- Lista numerada de contraseñas
- Confirmación antes de eliminar
- Eliminación permanente

### **5. 📊 Estadísticas**
- Total de contraseñas guardadas
- Últimas 5 contraseñas agregadas
- Información de cifrado

### **6. 🚪 Salir**
- Cierra la aplicación de forma segura

## 🔐 Seguridad

- **Autenticación requerida**: Usuario y contraseña de Django
- **Cifrado AES-256**: Todas las contraseñas están cifradas
- **Entrada segura**: Las contraseñas no se muestran al escribir
- **Sesión temporal**: No se almacenan credenciales en memoria

## 💡 Consejos de uso

1. **Crear superusuario** si no tienes uno:
   ```bash
   python manage.py createsuperuser
   ```

2. **Usar desde cualquier terminal** en el directorio del proyecto

3. **Salir siempre con opción 6** para cerrar correctamente

4. **Las contraseñas son las mismas** que en la interfaz web