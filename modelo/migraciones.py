"""Migración aditiva del esquema de Guru.

Crea tablas y columnas nuevas (roles, permisos, auditoría, bloqueo,
expiración de sesión, restablecimiento de clave, archivos, visitas). Es
idempotente: puede ejecutarse varias veces sin duplicar nada ni destruir
datos.

Se aplica automáticamente al arrancar la aplicación y también puede
ejecutarse a mano:  python -m modelo.migraciones
"""
from sqlalchemy import text
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
]

PERMISOS = [
    ("ver_productos", "Ver el catálogo de productos"),
    ("gestionar_productos", "Crear y editar productos"),
    ("gestionar_ventas", "Registrar y revisar ventas"),
    ("subir_archivos", "Subir archivos a la plataforma"),
    ("gestionar_usuarios", "Administrar usuarios y sus credenciales"),
    ("gestionar_roles", "Crear roles y asignar permisos"),
    ("ver_auditoria", "Consultar los registros de auditoría"),
]

ROLES_BASE = {"Usuario": ["ver_productos", "subir_archivos"]}
ROL_ADMIN = "Administrador"


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

        print("Sembrando permisos...")
        for codigo, descripcion in PERMISOS:
            c.execute(
                text("INSERT IGNORE INTO permiso (codigo, descripcion) VALUES (:codigo, :descripcion)"),
                {"codigo": codigo, "descripcion": descripcion},
            )

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


if __name__ == "__main__":
    ensure_esquema()
