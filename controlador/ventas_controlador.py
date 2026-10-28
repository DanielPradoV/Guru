import re
from flask import (
    Blueprint,
    render_template,
    request,
    session,
    redirect,
    url_for,
    current_app
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from modelo.conexion import engine
ventas_bp = Blueprint("ventas", __name__)
import secrets


@ventas_bp.before_app_request
def validar_sesion_activa():
    id_usuario = session.get("id_usuario")
    token = session.get("token_sesion")

    if id_usuario is None and token is None:
        return None

    if id_usuario is None or not token:
        session.clear()
        return None

    try:
        with engine.connect() as conexion:
            sesion_valida = conexion.execute(
                text("""
                    SELECT 1
                    FROM sesion_usuario
                    WHERE idUsuario = :id_usuario
                      AND tokenSesion = :token
                """),
                {
                    "id_usuario": id_usuario,
                    "token": token
                }
            ).first()

        if not sesion_valida:
            session.clear()

    except Exception:
        current_app.logger.exception(
            "Error al validar la sesión del usuario"
        )
        session.clear()

    return None



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


@ventas_bp.route("/login", methods=["POST"]) #ESTEEEEEEEEEEE
def login():
    correo = request.form.get("correo", "").strip().lower()
    contrasena = request.form.get("contrasena", "")

    if not correo or not contrasena:
        return render_template(
            "index.html",
            mensaje_login="Ingresa tu correo y contraseña."
        )

    try:
        with engine.connect() as conexion:
            usuario = conexion.execute(
                text("""
                    SELECT idUsuario, NombreCompleto, Clave
                    FROM usuario
                    WHERE Correo = :correo
                """),
                {"correo": correo}
            ).mappings().first()

        if not usuario or not check_password_hash(
            usuario["Clave"], contrasena
        ):
            return render_template(
                "index.html",
                mensaje_login="Correo o contraseña incorrectos."
            )

        token = secrets.token_urlsafe(32)

        with engine.begin() as conexion:
            sesion_existente = conexion.execute(
                text("""
                    SELECT idSesion
                    FROM sesion_usuario
                    WHERE idUsuario = :id_usuario
                """),
                {"id_usuario": usuario["idUsuario"]}
            ).first()

            if sesion_existente:
                return render_template(
                    "index.html",
                    mensaje_login=(
                        "Esta cuenta ya tiene una sesión activa. "
                        "Cierra esa sesión antes de volver a ingresar."
                    )
                )

            conexion.execute(
                text("""
                    INSERT INTO sesion_usuario
                        (idUsuario, tokenSesion)
                    VALUES
                        (:id_usuario, :token)
                """),
                {
                    "id_usuario": usuario["idUsuario"],
                    "token": token
                }
            )

        session.clear()
        session["id_usuario"] = usuario["idUsuario"]
        session["token_sesion"] = token

        return redirect(url_for("principal"))

    
    except IntegrityError:
        return render_template(
            "index.html",
            mensaje_login=(
                "Esta cuenta ya tiene una sesión activa. "
                "Cierra esa sesión antes de volver a ingresar."
            )
        )


    except Exception:
        current_app.logger.exception(
            "Error durante el inicio de sesión"
        )
        return render_template(
            "index.html",
            mensaje_login=(
                "No se pudo iniciar sesión. Inténtalo más tarde."
            )
        )


@ventas_bp.route("/logout", methods=["POST"])
def logout():
    id_usuario = session.get("id_usuario")
    token = session.get("token_sesion")

    try:
        if id_usuario is not None and token:
            with engine.begin() as conexion:
                conexion.execute(
                    text("""
                        DELETE FROM sesion_usuario
                        WHERE idUsuario = :id_usuario
                          AND tokenSesion = :token
                    """),
                    {
                        "id_usuario": id_usuario,
                        "token": token
                    }
                )

    except Exception:
        current_app.logger.exception(
            "Error al cerrar la sesión del usuario"
        )
        return (
            "No se pudo cerrar la sesión. Inténtalo de nuevo.",
            500
        )

    finally:
        session.clear()

    return redirect(url_for("inicio"))

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
