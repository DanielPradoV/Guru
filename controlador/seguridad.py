"""Utilidades de seguridad compartidas: auditoría, roles y permisos."""
import os

from functools import wraps
from datetime import timedelta

from flask import current_app, redirect, render_template, request, session, url_for
from sqlalchemy import text

from modelo.conexion import engine

# Configuración ajustable por variables de entorno
LOCK_MAX_INTENTOS = int(os.getenv("LOCK_MAX_INTENTOS", "5"))
LOCK_MINUTES = int(os.getenv("LOCK_MINUTES", "15"))

# Los tiempos de expiración se editan desde el panel de administración y
# viven en la tabla configuracion_seguridad. Estos valores de entorno son
# solo el respaldo: se usan cuando la tabla aún no existe (el arranque
# necesita sesion_timeout() antes de que corra la migración) o cuando la
# base de datos no responde.
VALORES_RESPALDO = {
    "sesion_minutos": int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")),
    "token_minutos": int(os.getenv("RESET_TOKEN_MINUTES", "30")),
}

CONFIGURACION = {
    "sesion_minutos": {
        "etiqueta": "Expiración de la sesión por inactividad",
        "ayuda": "Minutos sin actividad antes de que la aplicación cierre "
                 "la sesión (punto 11 del checklist).",
        "minimo": 1,
        "maximo": 720,
    },
    "token_minutos": {
        "etiqueta": "Expiración del token de autenticación",
        "ayuda": "Minutos de validez de los enlaces de verificación de "
                 "correo y de restablecimiento de contraseña (punto 10).",
        "minimo": 1,
        "maximo": 720,
    },
}


def configuracion_seguridad():
    """Lee los tiempos configurables; si la tabla no está disponible
    devuelve los respaldos de entorno para no romper el arranque."""
    valores = dict(VALORES_RESPALDO)

    try:
        with engine.connect() as conexion:
            filas = conexion.execute(
                text("SELECT clave, valor FROM configuracion_seguridad")
            ).fetchall()
    except Exception:
        return valores

    for clave, valor in filas:
        if clave in valores:
            try:
                valores[clave] = max(1, int(valor))
            except (TypeError, ValueError):
                pass

    return valores


def establecer_configuracion(clave, valor):
    """Guarda un tiempo editable (INSERT ... ON DUPLICATE para poder
    escribir aunque la siembra inicial no haya corrido)."""
    metadatos = CONFIGURACION[clave]

    with engine.begin() as conexion:
        conexion.execute(
            text("""
                INSERT INTO configuracion_seguridad
                    (clave, valor, descripcion, fechaActualizacion)
                VALUES (:clave, :valor, :descripcion, UTC_TIMESTAMP())
                ON DUPLICATE KEY UPDATE
                    valor = :valor,
                    fechaActualizacion = UTC_TIMESTAMP()
            """),
            {
                "clave": clave,
                "valor": int(valor),
                "descripcion": metadatos["etiqueta"],
            }
        )


def minutos_sesion():
    return configuracion_seguridad()["sesion_minutos"]


def minutos_token():
    return configuracion_seguridad()["token_minutos"]


def registrar_accion(accion, detalle=None, id_usuario=None):
    """Escribe un evento en la tabla auditoria. Nunca interrumpe la acción
    principal si el registro falla."""
    if id_usuario is None:
        id_usuario = session.get("id_usuario")

    try:
        with engine.begin() as conexion:
            conexion.execute(
                text("""
                    INSERT INTO auditoria (idUsuario, accion, detalle, direccionIp)
                    VALUES (:usuario, :accion, :detalle, :ip)
                """),
                {
                    "usuario": id_usuario,
                    "accion": accion,
                    "detalle": detalle,
                    "ip": (request.remote_addr or "")[:45] or None,
                }
            )
    except Exception:
        current_app.logger.exception("No se pudo registrar la acción de auditoría")


def obtener_permisos(id_usuario):
    with engine.connect() as conexion:
        filas = conexion.execute(
            text("""
                SELECT DISTINCT p.codigo
                FROM usuario_rol ur
                JOIN rol_permiso rp ON rp.idRol = ur.idRol
                JOIN permiso p ON p.idPermiso = rp.idPermiso
                WHERE ur.idUsuario = :u
            """),
            {"u": id_usuario},
        ).fetchall()
    return {f[0] for f in filas}


def requiere_permiso(codigo):
    def decorador(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            id_usuario = session.get("id_usuario")
            if id_usuario is None:
                return redirect(url_for("inicio"))
            if codigo not in obtener_permisos(id_usuario):
                return render_template("sin_permiso.html"), 403
            return vista(*args, **kwargs)
        return envoltura
    return decorador


def sesion_timeout():
    return timedelta(minutes=minutos_sesion())
