
import os
import resend
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("RESEND_API_KEY")
remitente = os.getenv("RESEND_FROM_EMAIL")

if not api_key or not remitente:
    raise RuntimeError("Falta configurar RESEND_API_KEY o RESEND_FROM_EMAIL")

resend.api_key = api_key

# Reemplaza este valor por el correo de tu cuenta de Resend.
destinatario = "danielverano016@gmail.com"

try:
    resultado = resend.Emails.send({
        "from": remitente,
        "to": [destinatario],
        "subject": "Prueba de correo - Guru",
        "html": """
            <h2>¡Hola!</h2>
            <p>Este es un correo de prueba de Guru.</p>
            <p>La conexión con Resend funciona correctamente.</p>
        """
    })

    print("Correo enviado correctamente.")
    print("ID del correo:", resultado["id"])

except Exception as error:
    print("Error al enviar el correo:")
    print(error)
