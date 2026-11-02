
import os
import csv
import hashlib
import json
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
    current_app,
    jsonify,
    send_from_directory,
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from modelo.conexion import engine

from controlador.seguridad import (
    LOCK_MAX_INTENTOS,
    LOCK_MINUTES,
    RESET_TOKEN_MINUTES,
    SESSION_TIMEOUT_MINUTES,
    VERIFICACION_TOKEN_MINUTES,
    registrar_accion,
    sesion_timeout,
)


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

            <p>Este enlace vence en {VERIFICACION_TOKEN_MINUTES} minutos.</p>

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
def reenviar_verificacion():
    
    print("========== ESTOY EJECUTANDO REENVIAR_VERIFICACION ==========", flush=True)
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
                                        INTERVAL :minutos MINUTE
                                    )
                                )
                            """),
                            {
                                "id_usuario": usuario["idUsuario"],
                                "token_hash": token_hash,
                                "minutos": VERIFICACION_TOKEN_MINUTES,
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



# Visitas: cada inicio de sesión abre una fila en `visita` y cada request
# de ese usuario mueve fechaFin. Así la duración siempre refleja el último
# instante de actividad real, aunque el navegador se cierre sin logout.
def registrar_actividad_visita(conexion, id_visita):

    if not id_visita:
        return

    conexion.execute(
        text("UPDATE visita SET fechaFin = UTC_TIMESTAMP() "
             "WHERE idVisita = :id"),
        {"id": id_visita}
    )


@ventas_bp.route("/keepalive", methods=["POST"])
def keepalive():
    """Latido del navegador: mantiene viva la sesión mientras la pestaña está abierta.

    La renovación de la expiración la hace validar_sesion_activa(); aquí
    solo se responde OK. Sin sesión devuelve 401 para que el front avise.
    """
    if "id_usuario" not in session:
        return jsonify(ok=False, expiro=True), 401
    return jsonify(ok=True)


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
        with engine.begin() as conexion:

            sesion = conexion.execute(
                text("""
                    SELECT idSesion,
                           (fechaExpiracion IS NOT NULL
                            AND fechaExpiracion <= UTC_TIMESTAMP()) AS expiro
                    FROM sesion_usuario
                    WHERE idUsuario = :id_usuario
                      AND tokenSesion = :token
                """),
                {
                    "id_usuario": id_usuario,
                    "token": token
                }
            ).mappings().first()

            if not sesion:
                session.clear()
                return None

            if sesion["expiro"]:
                conexion.execute(
                    text("DELETE FROM sesion_usuario WHERE idSesion = :id"),
                    {"id": sesion["idSesion"]}
                )
                registrar_actividad_visita(
                    conexion, session.get("id_visita")
                )
                session.clear()
                return None

            # Ventana deslizante: la actividad renuueva la expiración.
            conexion.execute(
                text("""
                    UPDATE sesion_usuario
                    SET fechaExpiracion = DATE_ADD(
                            UTC_TIMESTAMP(), INTERVAL :min MINUTE),
                        fechaUltimaActividad = UTC_TIMESTAMP()
                    WHERE idSesion = :id
                """),
                {"min": SESSION_TIMEOUT_MINUTES, "id": sesion["idSesion"]}
            )

            registrar_actividad_visita(
                conexion, session.get("id_visita")
            )

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

                    resultado = conexion.execute(
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

                    id_nuevo = resultado.lastrowid
                    if id_nuevo:
                        conexion.execute(
                            text("""
                                INSERT IGNORE INTO usuario_rol
                                    (idUsuario, idRol)
                                SELECT :u, idRol FROM rol
                                WHERE nombreRol = 'Usuario'
                            """),
                            {"u": id_nuevo}
                        )

                registrar_accion(
                    "registro_usuario",
                    f"Nuevo usuario registrado: {correo}",
                    id_usuario=id_nuevo,
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

    # Los eventos de auditoría se acumulan y se registran fuera de la
    # transacción: la FK de auditoria sobre usuario esperaría el lock
    # que esta misma transacción mantiene abierto (deadlock).
    eventos = []
    respuesta = None
    id_usuario = None
    token = None
    id_visita = None

    try:
        with engine.begin() as conexion:

            usuario = conexion.execute(
                text("""
                    SELECT idUsuario, NombreCompleto, Clave,
                           intentosFallidos,
                           fechaBloqueo > UTC_TIMESTAMP() AS bloqueado
                    FROM usuario
                    WHERE Correo = :correo
                """),
                {"correo": correo}
            ).mappings().first()

            if not usuario:
                respuesta = "Correo o contraseña incorrectos."

            elif usuario["bloqueado"]:
                restante = conexion.execute(
                    text("""
                        SELECT TIMESTAMPDIFF(
                            MINUTE, UTC_TIMESTAMP(), fechaBloqueo)
                        FROM usuario WHERE idUsuario = :u
                    """),
                    {"u": usuario["idUsuario"]}
                ).scalar() or 1
                eventos.append((
                    "intentos_bloqueado",
                    f"Intento con cuenta bloqueada para {correo}",
                    usuario["idUsuario"],
                ))
                respuesta = (
                    "La cuenta está bloqueada temporalmente por "
                    f"intentos fallidos. Espera {restante} minutos."
                )

            elif not check_password_hash(usuario["Clave"], contrasena):
                nuevos_intentos = usuario["intentosFallidos"] + 1
                if nuevos_intentos >= LOCK_MAX_INTENTOS:
                    conexion.execute(
                        text("""
                            UPDATE usuario
                            SET intentosFallidos = 0,
                                fechaBloqueo = DATE_ADD(
                                    UTC_TIMESTAMP(), INTERVAL :min MINUTE)
                            WHERE idUsuario = :u
                        """),
                        {"min": LOCK_MINUTES, "u": usuario["idUsuario"]}
                    )
                    eventos.append((
                        "cuenta_bloqueada",
                        f"Bloqueo por {LOCK_MAX_INTENTOS} intentos "
                        "fallidos",
                        usuario["idUsuario"],
                    ))
                    respuesta = (
                        f"La cuenta se bloqueó por {LOCK_MINUTES} minutos "
                        "tras varios intentos fallidos."
                    )
                else:
                    conexion.execute(
                        text(
                            "UPDATE usuario SET intentosFallidos = :i "
                            "WHERE idUsuario = :u"
                        ),
                        {"i": nuevos_intentos, "u": usuario["idUsuario"]}
                    )
                    eventos.append((
                        "login_fallido",
                        f"Contraseña incorrecta ({nuevos_intentos}/"
                        f"{LOCK_MAX_INTENTOS})",
                        usuario["idUsuario"],
                    ))
                    respuesta = "Correo o contraseña incorrectos."

            else:
                conexion.execute(
                    text(
                        "UPDATE usuario SET intentosFallidos = 0, "
                        "fechaBloqueo = NULL WHERE idUsuario = :u"
                    ),
                    {"u": usuario["idUsuario"]}
                )

                nuevo_token = secrets.token_urlsafe(32)

                sesion_existente = conexion.execute(
                    text("""
                        SELECT idSesion
                        FROM sesion_usuario
                        WHERE idUsuario = :id_usuario
                    """),
                    {"id_usuario": usuario["idUsuario"]}
                ).first()

                if sesion_existente:
                    respuesta = (
                        "Esta cuenta ya tiene una sesión activa. "
                        "Cierra esa sesión antes de volver a ingresar."
                    )
                else:
                    conexion.execute(
                        text("""
                            INSERT INTO sesion_usuario
                                (idUsuario, tokenSesion, fechaExpiracion)
                            VALUES (
                                :id_usuario,
                                :token,
                                DATE_ADD(UTC_TIMESTAMP(),
                                         INTERVAL :min MINUTE)
                            )
                        """),
                        {
                            "id_usuario": usuario["idUsuario"],
                            "token": nuevo_token,
                            "min": SESSION_TIMEOUT_MINUTES,
                        }
                    )

                    nueva_visita = conexion.execute(
                        text("""
                            INSERT INTO visita (idUsuario, fechaInicio)
                            VALUES (:u, UTC_TIMESTAMP())
                        """),
                        {"u": usuario["idUsuario"]},
                    )
                    id_visita = nueva_visita.lastrowid

                    eventos.append((
                        "login_exitoso",
                        f"Inicio de sesión de {correo}",
                        usuario["idUsuario"],
                    ))
                    id_usuario = usuario["idUsuario"]
                    token = nuevo_token

    except IntegrityError:
        respuesta = (
            "Esta cuenta ya tiene una sesión activa. "
            "Cierra esa sesión antes de volver a ingresar."
        )

    except Exception:
        current_app.logger.exception(
            "Error durante el inicio de sesión"
        )
        respuesta = "No se pudo iniciar sesión. Inténtalo más tarde."

    for accion, detalle, id_evento in eventos:
        registrar_accion(accion, detalle, id_usuario=id_evento)

    if respuesta:
        return render_template("index.html", mensaje_login=respuesta)

    session.clear()
    session.permanent = True
    session["id_usuario"] = id_usuario
    session["token_sesion"] = token
    session["id_visita"] = id_visita

    return redirect(url_for("principal"))


@ventas_bp.route("/logout", methods=["POST"])
def logout():

    id_usuario = session.get("id_usuario")
    token = session.get("token_sesion")
    id_visita = session.get("id_visita")

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

                registrar_actividad_visita(conexion, id_visita)

    except Exception:
        current_app.logger.exception(
            "Error al cerrar la sesión del usuario"
        )

        return (
            "No se pudo cerrar la sesión. Inténtalo de nuevo.",
            500
        )

    finally:
        registrar_accion(
            "cierre_sesion",
            id_usuario=id_usuario,
        )
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


# ---------------------------------------------------------------
# Carrito de compras de la página principal (estilo Dalliat)
# ---------------------------------------------------------------

DESCARGAS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "descargas"
)

NOMBRE_PEDIDO_RE = re.compile(r"^pedido_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.csv$")


@ventas_bp.route("/comprar", methods=["POST"])
def comprar():

    if "id_usuario" not in session:
        return jsonify(
            success=False, error="La sesión expiró. Inicia sesión de nuevo."
        ), 401

    try:
        productos = json.loads(request.form.get("productos", "[]"))
    except (ValueError, TypeError):
        return jsonify(success=False, error="Datos inválidos."), 400

    if not isinstance(productos, list) or not (1 <= len(productos) <= 100):
        return jsonify(
            success=False, error="El carrito debe tener entre 1 y 100 ítems."
        ), 400

    limpio = []
    for p in productos:
        if isinstance(p, dict) and p.get("nombre"):
            limpio.append({
                "nombre": str(p["nombre"])[:120],
                "precio": str(p.get("precio", ""))[:30],
            })

    if not limpio:
        return jsonify(success=False, error="Carrito vacío."), 400

    nombre_csv = (
        "pedido_"
        + datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        + ".csv"
    )

    try:
        os.makedirs(DESCARGAS_DIR, exist_ok=True)
        with open(
            os.path.join(DESCARGAS_DIR, nombre_csv),
            "w", newline="", encoding="utf-8",
        ) as archivo_csv:
            escritor = csv.writer(archivo_csv)
            escritor.writerow(["nombre", "precio"])
            for p in limpio:
                escritor.writerow([p["nombre"], p["precio"]])
    except Exception:
        current_app.logger.exception("Error al generar el pedido CSV")
        return jsonify(
            success=False, error="No se pudo registrar la compra."
        ), 500

    registrar_accion(
        "pedido_compra",
        f"{len(limpio)} productos: "
        + ", ".join(p["nombre"] for p in limpio)[:180],
    )

    return jsonify(
        success=True,
        message=(
            f"Compra registrada: {len(limpio)} productos."
        ),
        excel=nombre_csv,
    )


@ventas_bp.route("/descargas/<nombre>")
def descargar_pedido(nombre):

    if "id_usuario" not in session:
        return redirect(url_for("inicio"))

    # El nombre solo puede ser el generado por el propio servidor.
    if not NOMBRE_PEDIDO_RE.fullmatch(nombre):
        return "Nombre de archivo inválido.", 400

    return send_from_directory(DESCARGAS_DIR, nombre, as_attachment=True)
