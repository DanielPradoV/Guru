
import os
import hashlib
from datetime import datetime, timedelta
from dotenv import load_dotenv
import resend
import re
import secrets

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


# Configuración de Resend
load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")

REMITENTE = os.getenv(
    "RESEND_FROM_EMAIL",
    "Guru <onboarding@resend.dev>"
)

URL_BASE = os.getenv(
    "APP_BASE_URL",
    "http://127.0.0.1:5000"
)


# Enviar correo de verificación
def enviar_correo_verificacion(correo, nombre, token):

    enlace = url_for(
        "ventas.verificar_correo",
        token=token,
        _external=True
    )

    resultado = resend.Emails.send({
        "from": REMITENTE,
        "to": [correo],
        "subject": "Verifica tu correo electrónico - Guru",
        "html": f"""
            <h2>¡Bienvenido a Guru, {nombre}!</h2>

            <p>Gracias por crear tu cuenta.</p>

            <p>Para verificar tu correo electrónico,
            haz clic en el siguiente enlace:</p>

            <a href="{enlace}">
                Verificar mi correo
            </a>

            <p>Este enlace vence en 30 minutos.</p>

            <p>Si no creaste esta cuenta, ignora este mensaje.</p>
        """
    })

    return resultado


# Verificar correo electrónico
@ventas_bp.route("/verificar-correo/<token>")
def verificar_correo(token):

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    try:
        with engine.begin() as conexion:

            verificacion = conexion.execute(
                text("""
                    SELECT idVerificacion, idUsuario
                    FROM verificacion_correo
                    WHERE tokenHash = :token_hash
                      AND usado = FALSE
                      AND fechaExpiracion > UTC_TIMESTAMP()
                    FOR UPDATE
                """),
                {"token_hash": token_hash}
            ).mappings().first()

            if not verificacion:
                return render_template(
                    "verificacion.html",
                    mensaje=(
                        "El enlace es inválido, "
                        "ya fue utilizado o ha vencido."
                    ),
                    tipo_mensaje="error"
                )

            conexion.execute(
                text("""
                    UPDATE usuario
                    SET CorreoVerificado = TRUE
                    WHERE idUsuario = :id_usuario
                """),
                {
                    "id_usuario": verificacion["idUsuario"]
                }
            )

            conexion.execute(
                text("""
                    UPDATE verificacion_correo
                    SET usado = TRUE
                    WHERE idVerificacion = :id_verificacion
                """),
                {
                    "id_verificacion": verificacion["idVerificacion"]
                }
            )

        return render_template(
            "verificacion.html",
            mensaje=(
                "¡Tu correo fue verificado correctamente! "
                "Ya puedes iniciar sesión."
            ),
            tipo_mensaje="exito"
        )

    except Exception:
        current_app.logger.exception(
            "Error verificando el correo"
        )

        return render_template(
            "verificacion.html",
            mensaje=(
                "No se pudo verificar el correo. "
                "Inténtalo más tarde."
            ),
            tipo_mensaje="error"
        )


# Reenviar correo de verificación
@ventas_bp.route("/reenviar-verificacion", methods=["GET", "POST"])

# Reenviar correo de verificación
@ventas_bp.route("/reenviar-verificacion", methods=["GET", "POST"])
def reenviar_verificacion():

    mensaje = None
    tipo_mensaje = "error"

    if request.method == "POST":

        correo = request.form.get("correo", "").strip().lower()

        if not correo:
            mensaje = "Ingresa tu correo electrónico."

        else:
            try:
                token = secrets.token_urlsafe(32)

                token_hash = hashlib.sha256(
                    token.encode("utf-8")
                ).hexdigest()

                with engine.begin() as conexion:

                    usuario = conexion.execute(
                        text("""
                            SELECT idUsuario, NombreCompleto,
                                   Correo, CorreoVerificado
                            FROM usuario
                            WHERE Correo = :correo
                            FOR UPDATE
                        """),
                        {"correo": correo}
                    ).mappings().first()

                    if usuario and not usuario["CorreoVerificado"]:

                        # Invalidar tokens anteriores
                        conexion.execute(
                            text("""
                                UPDATE verificacion_correo
                                SET usado = TRUE
                                WHERE idUsuario = :id_usuario
                                  AND usado = FALSE
                            """),
                            {
                                "id_usuario": usuario["idUsuario"]
                            }
                        )

                        # Guardar el nuevo token
                        conexion.execute(
                            text("""
                                INSERT INTO verificacion_correo
                                    (idUsuario, tokenHash, fechaExpiracion)
                                VALUES (
                                    :id_usuario,
                                    :token_hash,
                                    DATE_ADD(
                                        UTC_TIMESTAMP(),
                                        INTERVAL 30 MINUTE
                                    )
                                )
                            """),
                            {
                                "id_usuario": usuario["idUsuario"],
                                "token_hash": token_hash
                            }
                        )

                        # Enviar el correo antes de confirmar la transacción
                        resultado = enviar_correo_verificacion(
                            usuario["Correo"],
                            usuario["NombreCompleto"],
                            token
                        )

                        print("\n========== RESEND ==========")
                        print("DEBUG: SE EJECUTÓ LA NUEVA FUNCIÓN DE REENVÍO")
                        print("Destinatario:", usuario["Correo"])
                        print("Respuesta:", repr(resultado))
                        print("============================\n")

                        mensaje = (
                            "El correo de verificación fue enviado "
                            "correctamente. Revisa tu bandeja de entrada."
                        )
                        tipo_mensaje = "exito"

                    else:
                        mensaje = (
                            "La cuenta no existe o ya tiene el correo "
                            "verificado."
                        )
                        tipo_mensaje = "error"

            except Exception as error:

                current_app.logger.exception(
                    "Error al reenviar el correo de verificación"
                )

                print("\n========== ERROR DE REENVÍO ==========")
                print("Tipo de error:", type(error).__name__)
                print("Detalle:", repr(error))
                print("======================================\n")

                mensaje = (
                    "No se pudo enviar el correo. "
                    "Inténtalo más tarde."
                )
                tipo_mensaje = "error"

    return render_template(
        "reenviar_verificacion.html",
        mensaje=mensaje,
        tipo_mensaje=tipo_mensaje
    )



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


@ventas_bp.route("/login", methods=["POST"])
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
