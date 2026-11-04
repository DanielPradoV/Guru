"""Envío de correo de Guru.

Dos proveedores, elegidos con las variables de entorno:

- SMTP directo (`SMTP_USER` + `SMTP_PASSWORD`): sin servicio externo y
  entrega a cualquier destinatario. Es la vía que usa Gmail con una
  "contraseña de aplicación".
- Resend (`RESEND_API_KEY`): se conserva como respaldo; en la cuenta de
  pruebas (sandbox) solo entrega al correo verificado del registro.

Si no hay ninguno configurado, `enviar` falla de forma explícita en lugar
de enviar a la basura el enlace de recuperación.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage

from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PUERTO = int(os.getenv("SMTP_PORT", "587"))
SMTP_USUARIO = os.getenv("SMTP_USER", "").strip()
SMTP_CLAVE = os.getenv("SMTP_PASSWORD", "")
# Gmail y la mayoría de relayes exigen que el remitente sea la propia
# cuenta autenticada; se puede añadir nombre visible, no otra dirección.
SMTP_DE = os.getenv("SMTP_FROM", "").strip()

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
REMITENTE_RESEND = os.getenv(
    "RESEND_FROM_EMAIL",
    "Guru <onboarding@resend.dev>"
)

TEXTO_ALTERNATIVO = (
    "Si no ves el mensaje, ábrelo en un navegador con soporte de HTML."
)


def proveedor_activo():
    """Nombre del proveedor que se usará, para logs y para el panel."""
    if SMTP_USUARIO and SMTP_CLAVE:
        return f"smtp:{SMTP_HOST}:{SMTP_PUERTO}"
    if RESEND_API_KEY:
        return "resend"
    return "ninguno"


def enviar(destinatario, asunto, html):
    """Envía un correo y devuelve una descripción de la respuesta.

    Lanza excepción si el envío no es posible: las rutas que llaman a este
    helper ya muestran un mensaje genérico de "inténtalo más tarde" y
    revierten la transacción, así que el token no queda colgado de un
    correo que nunca salió.
    """

    if proveedor_activo().startswith("smtp"):
        return _enviar_smtp(destinatario, asunto, html)

    if RESEND_API_KEY:
        return _enviar_resend(destinatario, asunto, html)

    raise RuntimeError(
        "No hay proveedor de correo configurado "
        "(SMTP_USER/SMTP_PASSWORD o RESEND_API_KEY)."
    )


def _enviar_smtp(destinatario, asunto, html):

    mensaje = EmailMessage()
    mensaje["From"] = SMTP_DE or SMTP_USUARIO
    mensaje["To"] = destinatario
    mensaje["Subject"] = asunto
    mensaje.set_content(TEXTO_ALTERNATIVO)
    mensaje.add_alternative(html, subtype="html")

    contexto = ssl.create_default_context()

    if SMTP_PUERTO == 465:
        servidor = smtplib.SMTP_SSL(
            SMTP_HOST, SMTP_PUERTO, context=contexto, timeout=20
        )
    else:
        servidor = smtplib.SMTP(SMTP_HOST, SMTP_PUERTO, timeout=20)
        servidor.ehlo()
        servidor.starttls(context=contexto)

    with servidor:
        servidor.login(SMTP_USUARIO, SMTP_CLAVE)
        rechazados = servidor.send_message(mensaje)

    if rechazados:
        raise RuntimeError(f"El servidor rechazó a: {', '.join(rechazados)}")

    return f"aceptado por {SMTP_HOST}:{SMTP_PUERTO}"


def _enviar_resend(destinatario, asunto, html):

    import resend

    resend.api_key = RESEND_API_KEY

    return resend.Emails.send({
        "from": REMITENTE_RESEND,
        "to": [destinatario],
        "subject": asunto,
        "html": html,
    })
