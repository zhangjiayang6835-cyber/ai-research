# fix_host_header.py
import os

def get_reset_link(token):
    """
    Genera un enlace de reseteo de contraseña seguro.
    Usa un dominio confiable en lugar del header Host.
    """
    trusted_host = os.environ.get('TRUSTED_HOST', 'tu-dominio-seguro.com')
    return f"https://{trusted_host}/reset?token={token}"

# Uso alternativo con validación
ALLOWED_HOSTS = ['tudominio.com', 'www.tudominio.com']

def get_reset_link_validated(token):
    """Genera un enlace validando el Host header."""
    # En un entorno real, request vendría de la petición HTTP
    # host = request.headers.get('Host')
    host = 'tudominio.com'  # Placeholder para ejemplo
    if host not in ALLOWED_HOSTS:
        host = ALLOWED_HOSTS[0]
    return f"https://{host}/reset?token={token}"