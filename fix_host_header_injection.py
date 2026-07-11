# fix_host_header_injection.py
import os

def get_reset_link(token):
    """
    Genera un enlace de reseteo de contraseña seguro.
    Usa un dominio confiable en lugar del header Host.
    """
    # Opción 1: Usar variable de entorno
    trusted_host = os.environ.get('TRUSTED_HOST', 'tu-dominio-seguro.com')
    return f"https://{trusted_host}/reset?token={token}"

# Opción 2: Validar Host header contra una lista blanca
ALLOWED_HOSTS = ['tudominio.com', 'www.tudominio.com']

def get_reset_link_with_validation(token):
    """
    Genera un enlace validando que el Host header sea confiable.
    """
    host = request.headers.get('Host')
    if host not in ALLOWED_HOSTS:
        # Rechazar o usar un host por defecto
        host = ALLOWED_HOSTS[0]
    return f"https://{host}/reset?token={token}"

# Ejemplo de uso en el contexto de una app web
def send_reset_email(email, token):
    reset_link = get_reset_link(token)
    # Aquí iría la lógica para enviar el correo
    print(f"Enlace de reseteo: {reset_link}")