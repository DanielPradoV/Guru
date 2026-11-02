"""Blueprint de administración: usuarios, roles, permisos y auditoría."""
from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from sqlalchemy import text
from werkzeug.security import generate_password_hash

from modelo.conexion import engine

from controlador.seguridad import (
    obtener_permisos,
    registrar_accion,
    requiere_permiso,
)

admin_bp = Blueprint("admin", __name__)


# -----------------------------------------------------------------
# Gestión de usuarios (puntos 6-7-8)
# -----------------------------------------------------------------

@admin_bp.route("/admin/usuarios")
@requiere_permiso("gestionar_usuarios")
def usuarios():

    with engine.connect() as conexion:
        filas = conexion.execute(
            text("""
                SELECT u.idUsuario, u.NombreCompleto, u.Correo,
                       u.Usuario, u.CorreoVerificado,
                       (u.fechaBloqueo > UTC_TIMESTAMP()) AS bloqueado
                FROM usuario u
                ORDER BY u.idUsuario
            """)
        ).mappings().fetchall()

        roles = conexion.execute(
            text("SELECT idRol, nombreRol FROM rol ORDER BY nombreRol")
        ).mappings().fetchall()

        asignaciones = conexion.execute(
            text("""
                SELECT ur.idUsuario, r.idRol
                FROM usuario_rol ur
                JOIN rol r ON r.idRol = ur.idRol
            """)
        ).fetchall()

    roles_usuario = {}
    for id_u, id_r in asignaciones:
        roles_usuario.setdefault(id_u, set()).add(id_r)

    return render_template(
        "admin_usuarios.html",
        usuarios=filas,
        roles=roles,
        roles_usuario=roles_usuario,
    )


@admin_bp.route("/admin/usuarios/<int:id_usuario>/clave", methods=["POST"])
@requiere_permiso("gestionar_usuarios")
def cambiar_clave(id_usuario):

    nueva = request.form.get("clave_nueva", "")

    # Un administrador tampoco puede imponer una contraseña débil.
    if len(nueva) < 8:
        mensaje = "La contraseña debe tener al menos 8 caracteres."
        tipo = "error"
    else:
        try:
            with engine.begin() as conexion:
                conectado = conexion.execute(
                    text("SELECT 1 FROM usuario WHERE idUsuario = :u"),
                    {"u": id_usuario}
                ).first()
                if not conectado:
                    mensaje = "El usuario no existe."
                    tipo = "error"
                else:
                    conexion.execute(
                        text("""
                            UPDATE usuario
                            SET Clave = :c,
                                intentosFallidos = 0,
                                fechaBloqueo = NULL
                            WHERE idUsuario = :u
                        """),
                        {
                            "c": generate_password_hash(nueva),
                            "u": id_usuario,
                        }
                    )
                    # Se cierran las sesiones activas del usuario.
                    conexion.execute(
                        text(
                            "DELETE FROM sesion_usuario "
                            "WHERE idUsuario = :u"
                        ),
                        {"u": id_usuario}
                    )
            registrar_accion(
                "cambio_clave_admin",
                f"El administrador cambió la contraseña del usuario "
                f"{id_usuario}",
            )
            mensaje = "Contraseña actualizada y sesiones cerradas."
            tipo = "exito"
        except Exception:
            current_app.logger.exception(
                "Error al cambiar la contraseña desde el panel"
            )
            mensaje = "No se pudo cambiar la contraseña."
            tipo = "error"

    return redirect(
        url_for("admin.usuarios", aviso=mensaje, tipo_aviso=tipo)
    )


@admin_bp.route("/admin/usuarios/<int:id_usuario>/roles", methods=["POST"])
@requiere_permiso("gestionar_roles")
def asignar_roles(id_usuario):

    ids = request.form.getlist("roles")
    ids = [i for i in ids if i.isdigit()]

    try:
        with engine.begin() as conexion:

            existe = conexion.execute(
                text("SELECT 1 FROM usuario WHERE idUsuario = :u"),
                {"u": id_usuario}
            ).first()
            if not existe:
                return redirect(url_for("admin.usuarios"))

            validos = conexion.execute(
                text("SELECT idRol FROM rol")
            ).fetchall()
            validos = {str(f[0]) for f in validos}
            ids = [i for i in ids if i in validos]

            conexion.execute(
                text("DELETE FROM usuario_rol WHERE idUsuario = :u"),
                {"u": id_usuario}
            )
            for id_rol in ids:
                conexion.execute(
                    text("""
                        INSERT INTO usuario_rol (idUsuario, idRol)
                        VALUES (:u, :r)
                    """),
                    {"u": id_usuario, "r": id_rol}
                )

        registrar_accion(
            "asignacion_roles",
            f"Roles {ids} asignados al usuario {id_usuario}",
        )
    except Exception:
        current_app.logger.exception("Error al asignar roles")

    return redirect(url_for("admin.usuarios"))


# -----------------------------------------------------------------
# Gestión de roles y permisos (puntos 5 y 8)
# -----------------------------------------------------------------

@admin_bp.route("/admin/roles", methods=["GET", "POST"])
@requiere_permiso("gestionar_roles")
def roles():

    mensaje = None
    tipo_mensaje = "error"

    if request.method == "POST":
        nombre = request.form.get("nombreRol", "").strip()

        if not nombre or len(nombre) > 50:
            mensaje = "El nombre del rol es obligatorio (máx. 50 chars)."
        else:
            try:
                with engine.begin() as conexion:
                    duplicado = conexion.execute(
                        text("SELECT 1 FROM rol WHERE nombreRol = :n"),
                        {"n": nombre}
                    ).first()
                    if duplicado:
                        mensaje = "Ya existe un rol con ese nombre."
                    else:
                        conexion.execute(
                            text(
                                "INSERT INTO rol (nombreRol) VALUES (:n)"
                            ),
                            {"n": nombre}
                        )
                        registrar_accion(
                            "crear_rol",
                            f"Rol '{nombre}' creado",
                        )
                        mensaje = f"Rol '{nombre}' creado."
                        tipo_mensaje = "exito"
            except Exception:
                current_app.logger.exception("Error al crear el rol")
                mensaje = "No se pudo crear el rol."

    with engine.connect() as conexion:
        lista_roles = conexion.execute(
            text("""
                SELECT idRol, nombreRol FROM rol ORDER BY nombreRol
            """)
        ).mappings().fetchall()

        permisos = conexion.execute(
            text("""
                SELECT idPermiso, codigo, descripcion
                FROM permiso ORDER BY codigo
            """)
        ).mappings().fetchall()

        asignados = conexion.execute(
            text("SELECT idRol, idPermiso FROM rol_permiso")
        ).fetchall()

    permisos_rol = {}
    for id_r, id_p in asignados:
        permisos_rol.setdefault(id_r, set()).add(id_p)

    return render_template(
        "admin_roles.html",
        roles=lista_roles,
        permisos=permisos,
        permisos_rol=permisos_rol,
        mensaje=mensaje,
        tipo_mensaje=tipo_mensaje,
    )


@admin_bp.route("/admin/roles/<int:id_rol>/permisos", methods=["POST"])
@requiere_permiso("gestionar_roles")
def editar_permisos(id_rol):

    ids = request.form.getlist("permisos")
    ids = [i for i in ids if i.isdigit()]

    try:
        with engine.begin() as conexion:

            rol = conexion.execute(
                text("SELECT nombreRol FROM rol WHERE idRol = :r"),
                {"r": id_rol}
            ).scalar()
            if not rol:
                return redirect(url_for("admin.roles"))

            validos = conexion.execute(
                text("SELECT idPermiso FROM permiso")
            ).fetchall()
            validos = {str(f[0]) for f in validos}
            ids = [i for i in ids if i in validos]

            conexion.execute(
                text("DELETE FROM rol_permiso WHERE idRol = :r"),
                {"r": id_rol}
            )
            for id_permiso in ids:
                conexion.execute(
                    text("""
                        INSERT INTO rol_permiso (idRol, idPermiso)
                        VALUES (:r, :p)
                    """),
                    {"r": id_rol, "p": id_permiso}
                )

        registrar_accion(
            "modificacion_permisos_rol",
            f"Permisos de '{rol}' reemplazados por {ids}",
        )
    except Exception:
        current_app.logger.exception("Error al editar permisos del rol")

    return redirect(url_for("admin.roles"))


# -----------------------------------------------------------------
# Visor de auditoría (punto 9)
# -----------------------------------------------------------------

@admin_bp.route("/auditoria")
@requiere_permiso("ver_auditoria")
def auditoria():

    filtro = request.args.get("accion", "").strip()[:60]

    try:
        with engine.connect() as conexion:
            if filtro:
                filas = conexion.execute(
                    text("""
                        SELECT a.fecha, u.Usuario, a.accion,
                               a.detalle, a.direccionIp
                        FROM auditoria a
                        LEFT JOIN usuario u
                            ON u.idUsuario = a.idUsuario
                        WHERE a.accion LIKE :f
                        ORDER BY a.fecha DESC, a.idAuditoria DESC
                        LIMIT 200
                    """),
                    {"f": f"{filtro}%"}
                ).mappings().fetchall()
            else:
                filas = conexion.execute(
                    text("""
                        SELECT a.fecha, u.Usuario, a.accion,
                               a.detalle, a.direccionIp
                        FROM auditoria a
                        LEFT JOIN usuario u
                            ON u.idUsuario = a.idUsuario
                        ORDER BY a.fecha DESC, a.idAuditoria DESC
                        LIMIT 200
                    """)
                ).mappings().fetchall()
    except Exception:
        current_app.logger.exception("Error al consultar la auditoría")
        filas = []

    return render_template("auditoria.html", eventos=filas, filtro=filtro)
