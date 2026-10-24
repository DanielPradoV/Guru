
from flask import Blueprint, render_template, request

ventas_bp = Blueprint("ventas", __name__)


@ventas_bp.route("/registro", methods=["GET", "POST"])
def registro():
    mensaje = None

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        contrasena = request.form.get("contrasena", "")
        confirmar = request.form.get("confirmar", "")

        if not nombre or not correo:
            mensaje = "Completa todos los campos."

        elif len(contrasena) < 8:
            mensaje = "La contraseña debe tener al menos 8 caracteres."

        elif contrasena != confirmar:
            mensaje = "Las contraseñas no coinciden."

        else:
            mensaje = (
                "Formulario validado. Todavía falta conectar la base de "
                "datos para guardar tu cuenta."
            )

    return render_template("registro.html", mensaje=mensaje)
