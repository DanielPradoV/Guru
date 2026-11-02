"""Utilidades de seguridad compartidas: auditoría, roles y permisos."""
import os

from functools import wraps
from datetime import timedelta

from flask import current_app, redirect, render_template, request, session, url_for
from sqlalchemy import text

from modelo.conexion import engine

# Configuración ajustable por variables de entorno
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
RESET_TOKEN_MINUTES = int(os.getenv("RESET_TOKEN_MINUTES", "30"))
VERIFICACION_TOKEN_MINUTES = int(os.getenv("VERIFICACION_TOKEN_MINUTES", "30"))
LOCK_MAX_INTENTOS = int(os.getenv("LOCK_MAX_INTENTOS", "5"))
LOCK_MINUTES = int(os.getenv("LOCK_MINUTES", "15"))


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
    return timedelta(minutes=SESSION_TIMEOUT_MINUTES)
