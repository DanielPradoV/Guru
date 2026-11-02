"""Migración aditiva del esquema de Guru.

Crea tablas y columnas nuevas (roles, permisos, auditoría, bloqueo,
expiración de sesión, restablecimiento de clave, archivos, visitas). Es
idempotente: puede ejecutarse varias veces sin duplicar nada ni destruir
datos.

Se aplica automáticamente al arrancar la aplicación y también puede
ejecutarse a mano:  python -m modelo.migraciones
"""
import os

from sqlalchemy import text
from werkzeug.security import generate_password_hash

from modelo.conexion import engine


def tabla_existe(conexion, nombre):
    return conexion.execute(
        text("""
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name = :t
        """),
        {"t": nombre},
    ).first()


def columna_existe(conexion, tabla, columna):
    return conexion.execute(
        text("""
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = DATABASE()
              AND table_name = :t AND column_name = :c
        """),
        {"t": tabla, "c": columna},
    ).first()


def agregar_columna(conexion, tabla, columna, definicion):
    if not columna_existe(conexion, tabla, columna):
        conexion.execute(text(f"ALTER TABLE {tabla} ADD COLUMN {columna} {definicion}"))
        print(f"  + columna {tabla}.{columna}")


DDL = [
    ("restablecimiento_clave", """
        CREATE TABLE IF NOT EXISTS restablecimiento_clave (
            idRestablecimiento INT AUTO_INCREMENT PRIMARY KEY,
            idUsuario INT NOT NULL,
            tokenHash VARCHAR(255) NOT NULL UNIQUE,
            usado TINYINT(1) NOT NULL DEFAULT 0,
            fechaExpiracion DATETIME NOT NULL,
            fechaCreacion TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_reset_usuario FOREIGN KEY (idUsuario)
                REFERENCES usuario (idUsuario) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("auditoria", """
        CREATE TABLE IF NOT EXISTS auditoria (
            idAuditoria INT AUTO_INCREMENT PRIMARY KEY,
            idUsuario INT NULL,
            accion VARCHAR(60) NOT NULL,
            detalle VARCHAR(255) NULL,
            direccionIp VARCHAR(45) NULL,
            fecha TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_auditoria_usuario FOREIGN KEY (idUsuario)
                REFERENCES usuario (idUsuario) ON DELETE SET NULL,
            INDEX idx_auditoria_fecha (fecha)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("rol", """
        CREATE TABLE IF NOT EXISTS rol (
            idRol INT AUTO_INCREMENT PRIMARY KEY,
            nombreRol VARCHAR(50) NOT NULL UNIQUE,
            fechaCreacion TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("permiso", """
        CREATE TABLE IF NOT EXISTS permiso (
            idPermiso INT AUTO_INCREMENT PRIMARY KEY,
            codigo VARCHAR(50) NOT NULL UNIQUE,
            descripcion VARCHAR(150) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("usuario_rol", """
        CREATE TABLE IF NOT EXISTS usuario_rol (
            idUsuario INT NOT NULL,
            idRol INT NOT NULL,
            PRIMARY KEY (idUsuario, idRol),
            CONSTRAINT fk_ur_usuario FOREIGN KEY (idUsuario)
                REFERENCES usuario (idUsuario) ON DELETE CASCADE,
            CONSTRAINT fk_ur_rol FOREIGN KEY (idRol)
                REFERENCES rol (idRol) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("rol_permiso", """
        CREATE TABLE IF NOT EXISTS rol_permiso (
            idRol INT NOT NULL,
            idPermiso INT NOT NULL,
            PRIMARY KEY (idRol, idPermiso),
            CONSTRAINT fk_rp_rol FOREIGN KEY (idRol)
                REFERENCES rol (idRol) ON DELETE CASCADE,
            CONSTRAINT fk_rp_permiso FOREIGN KEY (idPermiso)
                REFERENCES permiso (idPermiso) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("archivo", """
        CREATE TABLE IF NOT EXISTS archivo (
            idArchivo INT AUTO_INCREMENT PRIMARY KEY,
            idUsuario INT NOT NULL,
            nombreOriginal VARCHAR(255) NOT NULL,
            nombreAlmacenado VARCHAR(255) NOT NULL,
            mimeType VARCHAR(100) NOT NULL,
            tamanoBytes INT NOT NULL,
            fechaSubida TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_archivo_usuario FOREIGN KEY (idUsuario)
                REFERENCES usuario (idUsuario) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("visita", """
        CREATE TABLE IF NOT EXISTS visita (
            idVisita INT AUTO_INCREMENT PRIMARY KEY,
            idUsuario INT NOT NULL,
            fechaInicio DATETIME NOT NULL,
            fechaFin DATETIME NULL,
            CONSTRAINT fk_visita_usuario FOREIGN KEY (idUsuario)
                REFERENCES usuario (idUsuario) ON DELETE CASCADE,
            INDEX idx_visita_inicio (fechaInicio)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
    ("configuracion_seguridad", """
        CREATE TABLE IF NOT EXISTS configuracion_seguridad (
            clave VARCHAR(50) PRIMARY KEY,
            valor INT NOT NULL,
            descripcion VARCHAR(150) NOT NULL,
            fechaActualizacion DATETIME NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """),
]

PERMISOS = [
    ("ver_productos", "Ver el catálogo de productos"),
    ("gestionar_productos", "Crear y editar productos"),
    ("gestionar_ventas", "Registrar y revisar ventas"),
    ("subir_archivos", "Subir archivos a la plataforma"),
    ("gestionar_usuarios", "Administrar usuarios y sus credenciales"),
    ("gestionar_roles", "Crear roles y asignar permisos"),
    ("ver_auditoria", "Consultar los registros de auditoría"),
    ("gestionar_configuracion", "Ajustar los tiempos de expiración de sesión y de token"),
]

ROLES_BASE = {"Usuario": ["ver_productos", "subir_archivos"]}
ROL_ADMIN = "Administrador"
ROL_USUARIO_SEMILLA = "Usuario"

# Valores iniciales de los tiempos editables desde el panel. Solo se
# insertan si la clave no existe, para no pisar lo que ya decidió el
# administrador; la variable de entorno sigue siendo el respaldo cuando
# la tabla está vacía.
CONFIGURACION_BASE = [
    (
        "sesion_minutos",
        int(os.getenv("SESSION_TIMEOUT_MINUTES", "30")),
        "Minutos de inactividad antes de cerrar la sesión de la app",
    ),
    (
        "token_minutos",
        int(os.getenv("RESET_TOKEN_MINUTES", "30")),
        "Minutos de validez de los enlaces de verificación y de restablecimiento",
    ),
]


def ensure_esquema():
    with engine.begin() as c:
        print("Creando tablas nuevas...")
        for nombre, ddl in DDL:
            if not tabla_existe(c, nombre):
                c.execute(text(ddl))
                print(f"  + tabla {nombre}")
            else:
                print(f"  = tabla {nombre} ya existe")

        print("Agregando columnas de bloqueo y expiración...")
        agregar_columna(c, "usuario", "intentosFallidos", "TINYINT NOT NULL DEFAULT 0")
        agregar_columna(c, "usuario", "fechaBloqueo", "DATETIME NULL")
        agregar_columna(c, "sesion_usuario", "fechaExpiracion", "DATETIME NULL")
        agregar_columna(c, "sesion_usuario", "fechaUltimaActividad", "DATETIME NULL")

        # Las sesiones sin fecha de expiración son previas a esta migración:
        # nunca vencerían y bloquearían el nuevo inicio de sesión del usuario.
        borrar_muertas = c.execute(
            text("""
                DELETE FROM sesion_usuario
                WHERE fechaExpiracion IS NULL
                   OR fechaExpiracion <= UTC_TIMESTAMP()
            """)
        )
        if borrar_muertas.rowcount:
            print(f"  - {borrar_muertas.rowcount} sesiones muertas depuradas")

        print("Sembrando permisos...")
        permisos_nuevos = []
        for codigo, descripcion in PERMISOS:
            inserted = c.execute(
                text("INSERT IGNORE INTO permiso (codigo, descripcion) VALUES (:codigo, :descripcion)"),
                {"codigo": codigo, "descripcion": descripcion},
            ).rowcount
            if inserted:
                permisos_nuevos.append(codigo)
                print(f"  + permiso {codigo}")

        print("Sembrando roles base...")
        for nombre, codigos in ROLES_BASE.items():
            c.execute(text("INSERT IGNORE INTO rol (nombreRol) VALUES (:n)"), {"n": nombre})
            id_rol = c.execute(text("SELECT idRol FROM rol WHERE nombreRol = :n"), {"n": nombre}).scalar()
            for codigo in codigos:
                c.execute(
                    text("""
                        INSERT IGNORE INTO rol_permiso (idRol, idPermiso)
                        SELECT :r, p.idPermiso FROM permiso p WHERE p.codigo = :c
                    """),
                    {"r": id_rol, "c": codigo},
                )

        id_admin = c.execute(
            text("SELECT idRol FROM rol WHERE nombreRol = :n"), {"n": ROL_ADMIN}
        ).scalar()
        if id_admin is None:
            c.execute(text("INSERT INTO rol (nombreRol) VALUES (:n)"), {"n": ROL_ADMIN})
            id_admin = c.execute(
                text("SELECT idRol FROM rol WHERE nombreRol = :n"), {"n": ROL_ADMIN}
            ).scalar()

        # El rol Administrador recibe todos los permisos solo al crearlo;
        # después se administra desde el panel.
        if id_admin is not None:
            tiene = c.execute(
                text("SELECT 1 FROM rol_permiso WHERE idRol = :r LIMIT 1"), {"r": id_admin}
            ).first()
            if not tiene:
                c.execute(
                    text("INSERT INTO rol_permiso (idRol, idPermiso) SELECT :r, idPermiso FROM permiso"),
                    {"r": id_admin},
                )

        # Los permisos que esta migración acaba de estrenar se conceden al
        # Administrador para que la pestaña nueva sea alcanzable desde ya;
        # en relanzamientos siguientes ya no se re-escriben, así un permiso
        # retirado a mano desde el panel de Roles sigue retirado.
        if id_admin is not None and permisos_nuevos:
            for codigo in permisos_nuevos:
                c.execute(
                    text("""
                        INSERT IGNORE INTO rol_permiso (idRol, idPermiso)
                        SELECT :r, idPermiso FROM permiso WHERE codigo = :c
                    """),
                    {"r": id_admin, "c": codigo},
                )

        print("Sembrando configuración de seguridad...")
        for clave, valor, descripcion in CONFIGURACION_BASE:
            resultado = c.execute(
                text("""
                    INSERT IGNORE INTO configuracion_seguridad
                        (clave, valor, descripcion, fechaActualizacion)
                    VALUES (:clave, :valor, :descripcion, NULL)
                """),
                {"clave": clave, "valor": valor, "descripcion": descripcion},
            )
            if resultado.rowcount:
                print(f"  + {clave} = {valor} min")
            else:
                print(f"  = {clave} conserva su valor")

        print("Asignando rol Usuario a todos los usuarios existentes...")
        id_usuario_rol = c.execute(
            text("SELECT idRol FROM rol WHERE nombreRol = 'Usuario'")
        ).scalar()
        if id_usuario_rol:
            c.execute(
                text("""
                    INSERT IGNORE INTO usuario_rol (idUsuario, idRol)
                    SELECT u.idUsuario, :r FROM usuario u
                """),
                {"r": id_usuario_rol},
            )

        # El primer usuario registrado queda como administrador para poder
        # entrar al panel; se puede reasignar después desde la interfaz.
        primer_usuario = c.execute(
            text("SELECT idUsuario FROM usuario ORDER BY idUsuario LIMIT 1")
        ).scalar()
        if primer_usuario and id_admin:
            c.execute(
                text("INSERT IGNORE INTO usuario_rol (idUsuario, idRol) VALUES (:u, :r)"),
                {"u": primer_usuario, "r": id_admin},
            )
            print(f"  * usuario {primer_usuario} marcado como Administrador")

    print("Migración completada.")
    asegurar_administrador()


def asegurar_administrador():
    """Crea el administrador definido por ADMIN_EMAIL / ADMIN_PASSWORD.

    Render no da shell para correr scripts, así que el administrador se
    siembra al arrancar desde las variables de entorno. Si el correo ya
    existe solo se le asegura el rol Administrador; la contraseña nunca se
    reescribe, para no deshacer un cambio hecho desde el panel.
    """
    correo = os.getenv("ADMIN_EMAIL", "").strip().lower()
    clave = os.getenv("ADMIN_PASSWORD", "")

    if not correo or not clave:
        return

    if len(clave) < 8:
        print("  ! ADMIN_PASSWORD es demasiado corta (mínimo 8); se omite")
        return

    with engine.begin() as c:
        existente = c.execute(
            text("SELECT idUsuario FROM usuario WHERE Correo = :c"),
            {"c": correo},
        ).scalar()

        if existente:
            id_usuario = existente
            creado = False
        else:
            usuario = (os.getenv("ADMIN_USUARIO") or correo.split("@")[0])[:50]
            nombre = (os.getenv("ADMIN_NOMBRE") or "Administrador")[:100]
            resultado = c.execute(
                text("""
                    INSERT INTO usuario
                        (NombreCompleto, Correo, Usuario, Clave,
                         CorreoVerificado)
                    VALUES (:nombre, :correo, :usuario, :clave, TRUE)
                """),
                {
                    "nombre": nombre,
                    "correo": correo,
                    "usuario": usuario,
                    "clave": generate_password_hash(clave),
                },
            )
            id_usuario = resultado.lastrowid
            creado = True

        for nombre_rol in (ROL_USUARIO_SEMILLA, ROL_ADMIN):
            id_rol = c.execute(
                text("SELECT idRol FROM rol WHERE nombreRol = :n"),
                {"n": nombre_rol},
            ).scalar()
            if id_rol:
                c.execute(
                    text("""
                        INSERT IGNORE INTO usuario_rol (idUsuario, idRol)
                        VALUES (:u, :r)
                    """),
                    {"u": id_usuario, "r": id_rol},
                )

        print(
            f"  {'*' if creado else '='} administrador "
            f"{'creado' if creado else 'ya existía'}: {correo} "
            f"(id {id_usuario})"
        )


if __name__ == "__main__":
    ensure_esquema()
