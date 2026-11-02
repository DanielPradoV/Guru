"""Blueprint de cuenta: recuperación de clave, perfil y subida de archivos."""
import hashlib
import os
import re
import secrets
import uuid

import resend
from dotenv import load_dotenv

from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

from modelo.conexion import engine

from controlador.seguridad import (
    RESET_TOKEN_MINUTES,
    registrar_accion,
)

cuenta_bp = Blueprint("cuenta", __name__)

load_dotenv()
resend.api_key = os.getenv("RESEND_API_KEY")
REMITENTE = os.getenv(
    "RESEND_FROM_EMAIL",
    "Guru <onboarding@resend.dev>"
)

RUTA_SUBIDAS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "Subidas"
)

# Extensiones permitidas y su firma binaria real (magic bytes).
MAGICOS = {
    "pdf": [b"%PDF"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "gif": [b"GIF8"],
    "webp": [b"RIFF"],  # se confirma WEBP en desplaz 8
}


# -----------------------------------------------------------------
# Recuperación de contraseña (punto 3)
# -----------------------------------------------------------------

def enviar_correo_restablecimiento(correo, nombre, token):

    enlace = url_for(
        "cuenta.restablecer_contrasena",
        token=token,
        _external=True
    )

    return resend.Emails.send({
        "from": REMITENTE,
        "to": [correo],
        "subject": "Restablece tu contraseña - Guru",
        "html": f"""
            <h2>Hola, {nombre}</h2>
            <p>Recibimos una solicitud para restablecer tu contraseña
            en Guru.</p>
            <a href="{enlace}">Restablecer mi contraseña</a>
            <p>Este enlace vence en {RESET_TOKEN_MINUTES} minutos y
            solo puede usarse una vez.</p>
            <p>Si no solicitaste el cambio, ignora este mensaje; tu
            contraseña actual seguirá siendo válida.</p>
        """
    })


@cuenta_bp.route("/recuperar-contrasena", methods=["GET", "POST"])
def recuperar_contrasena():

    mensaje = None
    tipo_mensaje = "error"

    if request.method == "POST":

        correo = request.form.get("correo", "").strip().lower()

        if not correo:
            mensaje = "Ingresa tu correo electrónico."
        else:
            usuario_id = None
            try:
                with engine.begin() as conexion:

                    usuario = conexion.execute(
                        text("""
                            SELECT idUsuario, NombreCompleto, Correo
                            FROM usuario
                            WHERE Correo = :correo
                            FOR UPDATE
                        """),
                        {"correo": correo}
                    ).mappings().first()

                    if usuario:

                        conexion.execute(
                            text("""
                                UPDATE restablecimiento_clave
                                SET usado = TRUE
                                WHERE idUsuario = :id_usuario
                                  AND usado = FALSE
                            """),
                            {"id_usuario": usuario["idUsuario"]}
                        )

                        token = secrets.token_urlsafe(32)
                        token_hash = hashlib.sha256(
                            token.encode("utf-8")
                        ).hexdigest()

                        conexion.execute(
                            text("""
                                INSERT INTO restablecimiento_clave
                                    (idUsuario, tokenHash, fechaExpiracion)
                                VALUES (
                                    :id_usuario,
                                    :token_hash,
                                    DATE_ADD(UTC_TIMESTAMP(),
                                             INTERVAL :minutos MINUTE)
                                )
                            """),
                            {
                                "id_usuario": usuario["idUsuario"],
                                "token_hash": token_hash,
                                "minutos": RESET_TOKEN_MINUTES,
                            }
                        )

                        enviar_correo_restablecimiento(
                            usuario["Correo"],
                            usuario["NombreCompleto"],
                            token
                        )

                        usuario_id = usuario["idUsuario"]

                # La auditoría se registra fuera de la transacción para
                # no esperar el lock sobre la fila de usuario.
                if usuario_id:
                    registrar_accion(
                        "restablecimiento_solicitado",
                        f"Solicitud de cambio de clave para {correo}",
                        id_usuario=usuario_id,
                    )

                # Respuesta genérica a propósito: no revelamos si el
                # correo existe o no en la base de datos.
                mensaje = (
                    "Si el correo está registrado, enviamos un enlace "
                    "para restablecer la contraseña."
                )
                tipo_mensaje = "exito"

            except Exception:
                current_app.logger.exception(
                    "Error al solicitar el restablecimiento de clave"
                )
                mensaje = (
                    "No se pudo procesar la solicitud. Inténtalo más tarde."
                )

    return render_template(
        "recuperar_contrasena.html",
        mensaje=mensaje,
        tipo_mensaje=tipo_mensaje
    )


@cuenta_bp.route("/restablecer-contrasena/<token>", methods=["GET", "POST"])
def restablecer_contrasena(token):

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    mensaje = None
    tipo_mensaje = "error"

    try:
        with engine.connect() as conexion:
            registro = conexion.execute(
                text("""
                    SELECT idRestablecimiento, idUsuario
                    FROM restablecimiento_clave
                    WHERE tokenHash = :th
                      AND usado = FALSE
                      AND fechaExpiracion > UTC_TIMESTAMP()
                """),
                {"th": token_hash}
            ).mappings().first()
    except Exception:
        current_app.logger.exception(
            "Error validando token de restablecimiento"
        )
        registro = None

    if not registro:
        return render_template(
            "mensaje.html",
            mensaje=(
                "El enlace es inválido, ya fue utilizado o ha vencido. "
                "Solicita un nuevo restablecimiento."
            ),
            tipo_mensaje="error",
        ), 400

    if request.method == "POST":

        contrasena = request.form.get("contrasena", "")
        confirmar = request.form.get("confirmar", "")

        if len(contrasena) < 8:
            mensaje = "La contraseña debe tener al menos 8 caracteres."
            tipo_mensaje = "error"
        elif contrasena != confirmar:
            mensaje = "Las contraseñas no coinciden."
            tipo_mensaje = "error"
        else:
            try:
                with engine.begin() as conexion:

                    conexion.execute(
                        text("""
                            UPDATE usuario
                            SET Clave = :clave,
                                intentosFallidos = 0,
                                fechaBloqueo = NULL
                            WHERE idUsuario = :u
                        """),
                        {
                            "clave": generate_password_hash(contrasena),
                            "u": registro["idUsuario"],
                        }
                    )

                    conexion.execute(
                        text("""
                            UPDATE restablecimiento_clave
                            SET usado = TRUE
                            WHERE idRestablecimiento = :r
                        """),
                        {"r": registro["idRestablecimiento"]}
                    )

                    # Por seguridad se cierran todas las sesiones activas.
                    conexion.execute(
                        text(
                            "DELETE FROM sesion_usuario "
                            "WHERE idUsuario = :u"
                        ),
                        {"u": registro["idUsuario"]}
                    )

                registrar_accion(
                    "clave_restablecida",
                    "Contraseña cambiada mediante restablecimiento "
                    "por correo",
                    id_usuario=registro["idUsuario"],
                )

                session.clear()
                return render_template(
                    "mensaje.html",
                    mensaje=(
                        "Tu contraseña fue actualizada. "
                        "Inicia sesión con la nueva contraseña."
                    ),
                    tipo_mensaje="exito",
                )

            except Exception:
                current_app.logger.exception(
                    "Error al restablecer la contraseña"
                )
                mensaje = (
                    "No se pudo cambiar la contraseña. "
                    "Inténtalo más tarde."
                )
                tipo_mensaje = "error"

    return render_template(
        "restablecer_contrasena.html",
        mensaje=mensaje,
        tipo_mensaje=tipo_mensaje
    )


# -----------------------------------------------------------------
# Perfil del usuario (punto 20)
# -----------------------------------------------------------------

@cuenta_bp.route("/perfil", methods=["GET", "POST"])
def perfil():

    id_usuario = session.get("id_usuario")
    if id_usuario is None:
        return redirect(url_for("inicio"))

    mensaje = None
    tipo_mensaje = "exito"

    if request.method == "POST":

        formulario = request.form.get("formulario", "")

        if formulario == "datos":

            nombre = request.form.get("nombre", "").strip()
            correo = request.form.get("correo", "").strip().lower()
            usuario = request.form.get("usuario", "").strip()

            patron = r"^[a-zA-ZáéíóúÁÉÍÓÚñÑüÜ0-9 .@_]+$"

            if not all([nombre, correo, usuario]):
                mensaje = "Completa todos los campos."
                tipo_mensaje = "error"
            elif (len(nombre) > 100 or len(usuario) > 50
                  or len(correo) > 254):
                mensaje = "Uno de los campos supera la longitud máxima."
                tipo_mensaje = "error"
            elif (not re.fullmatch(patron, nombre)
                  or not re.fullmatch(patron, usuario)):
                mensaje = "Los campos contienen caracteres no permitidos."
                tipo_mensaje = "error"
            elif "@" not in correo or "." not in correo.split("@")[-1]:
                mensaje = "Ingresa un correo electrónico válido."
                tipo_mensaje = "error"
            else:
                try:
                    with engine.begin() as conexion:
                        conexion.execute(
                            text("""
                                UPDATE usuario
                                SET NombreCompleto = :n,
                                    Correo = :c,
                                    Usuario = :u,
                                    CorreoVerificado = FALSE
                                WHERE idUsuario = :id
                            """),
                            {
                                "n": nombre,
                                "c": correo,
                                "u": usuario,
                                "id": id_usuario,
                            }
                        )
                    registrar_accion(
                        "actualizacion_perfil",
                        f"Cambio de datos de perfil (correo: {correo})",
                        id_usuario=id_usuario,
                    )
                    mensaje = (
                        "Perfil actualizado. El nuevo correo quedó "
                        "pendiente de verificación."
                    )
                except IntegrityError:
                    mensaje = (
                        "El correo o el nombre de usuario ya están "
                        "registrados."
                    )
                    tipo_mensaje = "error"
                except Exception:
                    current_app.logger.exception(
                        "Error al actualizar el perfil"
                    )
                    mensaje = "No se pudo actualizar el perfil."
                    tipo_mensaje = "error"

        elif formulario == "clave":

            actual = request.form.get("clave_actual", "")
            nueva = request.form.get("clave_nueva", "")
            confirmar = request.form.get("clave_confirmar", "")

            try:
                with engine.connect() as conexion:
                    fila = conexion.execute(
                        text(
                            "SELECT Clave FROM usuario "
                            "WHERE idUsuario = :id"
                        ),
                        {"id": id_usuario}
                    ).mappings().first()

                if not fila or not check_password_hash(
                    fila["Clave"], actual
                ):
                    mensaje = "La contraseña actual es incorrecta."
                    tipo_mensaje = "error"
                elif len(nueva) < 8:
                    mensaje = (
                        "La nueva contraseña debe tener al menos "
                        "8 caracteres."
                    )
                    tipo_mensaje = "error"
                elif nueva != confirmar:
                    mensaje = "La confirmación no coincide."
                    tipo_mensaje = "error"
                elif nueva == actual:
                    mensaje = (
                        "La nueva contraseña debe ser distinta "
                        "a la actual."
                    )
                    tipo_mensaje = "error"
                else:
                    with engine.begin() as conexion:
                        conexion.execute(
                            text(
                                "UPDATE usuario SET Clave = :clave "
                                "WHERE idUsuario = :id"
                            ),
                            {
                                "clave": generate_password_hash(nueva),
                                "id": id_usuario,
                            }
                        )
                    registrar_accion(
                        "cambio_clave_propia",
                        "El usuario cambió su contraseña desde el perfil",
                        id_usuario=id_usuario,
                    )
                    mensaje = "Contraseña actualizada correctamente."
            except Exception:
                current_app.logger.exception(
                    "Error al cambiar la contraseña"
                )
                mensaje = "No se pudo cambiar la contraseña."
                tipo_mensaje = "error"

    try:
        with engine.connect() as conexion:
            datos = conexion.execute(
                text("""
                    SELECT NombreCompleto, Correo, Usuario,
                           CorreoVerificado
                    FROM usuario WHERE idUsuario = :id
                """),
                {"id": id_usuario}
            ).mappings().first()

            roles = conexion.execute(
                text("""
                    SELECT r.nombreRol
                    FROM usuario_rol ur
                    JOIN rol r ON r.idRol = ur.idRol
                    WHERE ur.idUsuario = :id
                """),
                {"id": id_usuario}
            ).fetchall()
    except Exception:
        current_app.logger.exception("Error al consultar el perfil")
        datos = None
        roles = []

    if not datos:
        session.clear()
        return redirect(url_for("inicio"))

    return render_template(
        "perfil.html",
        datos=datos,
        roles=[r[0] for r in roles],
        mensaje=mensaje,
        tipo_mensaje=tipo_mensaje,
    )


# -----------------------------------------------------------------
# Subida de archivos con validación de contenido (punto 15)
# -----------------------------------------------------------------

def tipo_real_por_magicos(cabecera, extension):
    """Devuelve None si el contenido binario no corresponde con una
    extensión permitida. Detecta p.ej. un .exe renombrado como .pdf."""
    if cabecera[:2] == b"MZ":
        return "ejecutable"
    firmas = MAGICOS.get(extension, [])
    for firma in firmas:
        if cabecera.startswith(firma):
            if extension == "webp":
                return "webp" if cabecera[8:12] == b"WEBP" else None
            return extension
    return None


@cuenta_bp.route("/subidas", methods=["GET", "POST"])
def subidas():

    id_usuario = session.get("id_usuario")
    if id_usuario is None:
        return redirect(url_for("inicio"))

    mensaje = None
    tipo_mensaje = "exito"

    if request.method == "POST":

        archivo = request.files.get("archivo")

        if not archivo or not archivo.filename:
            mensaje = "Selecciona un archivo para subir."
            tipo_mensaje = "error"
        else:
            nombre_original = os.path.basename(archivo.filename)
            extension = nombre_original.rsplit(".", 1)[-1].lower() \
                if "." in nombre_original else ""

            cabecera = archivo.read(4096)
            archivo.seek(0)

            tipo = tipo_real_por_magicos(cabecera, extension)

            if extension not in MAGICOS:
                mensaje = (
                    "Extensión no permitida. Solo se aceptan "
                    "PDF, PNG, JPG, GIF y WEBP."
                )
                tipo_mensaje = "error"
            elif tipo == "ejecutable":
                mensaje = (
                    "Contenido rechazado: el archivo es un ejecutable "
                    "aunque la extensión diga otra cosa."
                )
                tipo_mensaje = "error"
                registrar_accion(
                    "subida_rechazada",
                    f"Ejecutable disfrazado de .{extension}: "
                    f"{nombre_original}",
                )
            elif tipo is None:
                mensaje = (
                    f"El contenido del archivo no corresponde con la "
                    f"extensión .{extension} declarada."
                )
                tipo_mensaje = "error"
                registrar_accion(
                    "subida_rechazada",
                    f"Contenido no coincidente con .{extension}: "
                    f"{nombre_original}",
                )
            else:
                try:
                    os.makedirs(RUTA_SUBIDAS, exist_ok=True)
                    nombre_almacenado = (
                        f"{uuid.uuid4().hex}.{extension}"
                    )
                    archivo.save(
                        os.path.join(RUTA_SUBIDAS, nombre_almacenado)
                    )

                    tamano = os.path.getsize(
                        os.path.join(RUTA_SUBIDAS, nombre_almacenado)
                    )

                    with engine.begin() as conexion:
                        conexion.execute(
                            text("""
                                INSERT INTO archivo
                                    (idUsuario, nombreOriginal,
                                     nombreAlmacenado, mimeType,
                                     tamanoBytes)
                                VALUES
                                    (:u, :no, :na, :mt, :tb)
                            """),
                            {
                                "u": id_usuario,
                                "no": nombre_original[:255],
                                "na": nombre_almacenado,
                                "mt": (
                                    archivo.mimetype or ""
                                )[:100],
                                "tb": tamano,
                            }
                        )

                    registrar_accion(
                        "subida_archivo",
                        f"{nombre_original} ({tamano} bytes)",
                        id_usuario=id_usuario,
                    )
                    mensaje = (
                        f"{nombre_original} se subió correctamente."
                    )
                except Exception:
                    current_app.logger.exception(
                        "Error al guardar el archivo subido"
                    )
                    mensaje = "No se pudo guardar el archivo."
                    tipo_mensaje = "error"

    try:
        with engine.connect() as conexion:
            mios = conexion.execute(
                text("""
                    SELECT idArchivo, nombreOriginal, tamanoBytes,
                           mimeType, fechaSubida
                    FROM archivo
                    WHERE idUsuario = :u
                    ORDER BY fechaSubida DESC
                    LIMIT 50
                """),
                {"u": id_usuario}
            ).mappings().fetchall()
    except Exception:
        current_app.logger.exception("Error al listar archivos")
        mios = []

    return render_template(
        "subidas.html",
        archivos=mios,
        mensaje=mensaje,
        tipo_mensaje=tipo_mensaje,
    )


@cuenta_bp.route("/subidas/<int:id_archivo>/descargar")
def descargar_archivo(id_archivo):

    id_usuario = session.get("id_usuario")
    if id_usuario is None:
        return redirect(url_for("inicio"))

    try:
        with engine.connect() as conexion:
            fila = conexion.execute(
                text("""
                    SELECT nombreAlmacenado, nombreOriginal, idUsuario
                    FROM archivo WHERE idArchivo = :id
                """),
                {"id": id_archivo}
            ).mappings().first()
    except Exception:
        current_app.logger.exception("Error al buscar el archivo")
        return render_template(
            "mensaje.html",
            mensaje="No se pudo consultar el archivo.",
            tipo_mensaje="error",
        ), 500

    if not fila:
        return render_template(
            "mensaje.html",
            mensaje="El archivo no existe.",
            tipo_mensaje="error",
        ), 404

    if fila["idUsuario"] != id_usuario:
        from controlador.seguridad import obtener_permisos
        if "gestionar_usuarios" not in obtener_permisos(id_usuario):
            return render_template("sin_permiso.html"), 403

    return send_from_directory(
        RUTA_SUBIDAS,
        fila["nombreAlmacenado"],
        as_attachment=True,
        download_name=fila["nombreOriginal"],
    )
