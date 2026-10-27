import re
from flask import Blueprint, render_template, request
from werkzeug.security import generate_password_hash
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from modelo.conexion import engine
ventas_bp = Blueprint("ventas", __name__)



@ventas_bp.route("/registro", methods=["GET", "POST"])
def registro():
    mensaje = None
    tipo_mensaje = "error"

    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        usuario = request.form.get("usuario", "").strip()
        contrasena = request.form.get("contrasena", "")
        confirmar = request.form.get("confirmar", "")

        if not all([nombre, correo, usuario, contrasena, confirmar]):
            mensaje = "Completa todos los campos."

        elif len(nombre) > 100:
            mensaje = "El nombre no puede superar los 100 caracteres."

        elif len(correo) > 254:
            mensaje = "El correo es demasiado largo."

        elif len(usuario) > 50:
            mensaje = "El usuario no puede superar los 50 caracteres."

        elif "@" not in correo or "." not in correo.split("@")[-1]:
            mensaje = "Ingresa un correo electrónico válido."

        elif len(contrasena) < 8:
            mensaje = "La contraseña debe tener al menos 8 caracteres."

        elif contrasena != confirmar:
            mensaje = "Las contraseñas no coinciden."

        else:
            clave_hash = generate_password_hash(contrasena)

            try:
                with engine.begin() as conexion:
                    conexion.execute(
                        text("""
                            INSERT INTO usuario
                                (NombreCompleto, Correo, Usuario, Clave)
                            VALUES
                                (:nombre, :correo, :usuario, :clave)
                        """),
                        {
                            "nombre": nombre,
                            "correo": correo,
                            "usuario": usuario,
                            "clave": clave_hash
                        }
                    )

                mensaje = "¡Tu cuenta se creó correctamente!"
                tipo_mensaje = "exito"

            except IntegrityError:
                mensaje = (
                    "El correo o el nombre de usuario ya están registrados."
                )

            except Exception:
                from flask import current_app

                current_app.logger.exception(
                    "Error al registrar usuario en la base de datos"
                )

                mensaje = (
                    "No se pudo completar el registro. "
                    "Revisa los logs del servidor."
                )

    return render_template(
        "registro.html",
        mensaje=mensaje,
        tipo_mensaje=tipo_mensaje
    )


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
