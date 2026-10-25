import re
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

        patron_nombre = r"^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9 .@_]+$"

        patron_correo = r"^[a-zA-Z0-9._]+@[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$"

        if not nombre or not correo or not contrasena or not confirmar:
            mensaje = "Completa todos los campos."

        elif not re.fullmatch(patron_nombre, nombre):
            mensaje = (
                "El nombre solo puede contener letras, números, "
                "espacios y los caracteres . @ _"
            )

        elif not re.fullmatch(patron_correo, correo):
            mensaje = (
                "El correo solo puede contener letras, números "
                "y los caracteres . @ _ en un formato válido."
            )

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


@ventas_bp.route("/registro-vendedor", methods=["GET", "POST"])
def registro_vendedor():
    mensaje = None

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        negocio = request.form.get("negocio", "").strip()
        nit = request.form.get("nit", "").strip()
        contrasena = request.form.get("contrasena", "")
        confirmar = request.form.get("confirmar", "")

        patron_nombre = r"^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9 .@_]+$"
        patron_correo = r"^[a-zA-Z0-9._]+@[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)+$"
        patron_nit = r"^[0-9]{9,10}(-[0-9])?$"

        if not all([nombre, correo, negocio, nit, contrasena, confirmar]):
            mensaje = "Completa todos los campos."

        elif not re.fullmatch(patron_nombre, nombre):
            mensaje = "El nombre contiene caracteres no permitidos."

        elif not re.fullmatch(patron_correo, correo):
            mensaje = "Ingresa un correo electrónico válido."

        elif not re.fullmatch(patron_nombre, negocio):
            mensaje = "El nombre del negocio contiene caracteres no permitidos."

        elif not re.fullmatch(patron_nit, nit):
            mensaje = "El NIT no tiene un formato válido."

        elif len(contrasena) < 8:
            mensaje = "La contraseña debe tener al menos 8 caracteres."

        elif contrasena != confirmar:
            mensaje = "Las contraseñas no coinciden."

        else:
            mensaje = (
                "Datos validados correctamente. Falta conectar la "
                "base de datos para guardar tu cuenta de vendedor."
            )

    return render_template(
        "registro_vendedor.html",
        mensaje=mensaje
    )
