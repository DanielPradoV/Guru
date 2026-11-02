"""Crea o promueve un usuario administrador desde la línea de comandos.

Uso:
    python scripts/crear_admin.py correo@dominio.com "ClaveSegura12"
    python scripts/crear_admin.py correo@dominio.com "ClaveSegura12" usuario "Nombre Apellido"
    python scripts/crear_admin.py --promover correo@dominio.com

En Render (sin shell por defecto) se puede habilitar "Generate Deploy
Endpoint" / Advanced → Root Shell y ejecutar el mismo comando, o crear el
usuario desde /registro y luego promoverlo.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text
from werkzeug.security import generate_password_hash

from modelo.conexion import engine
from modelo.migraciones import ensure_esquema

ROL_ADMIN = "Administrador"
ROL_USUARIO = "Usuario"


def id_rol(conexion, nombre):
    return conexion.execute(
        text("SELECT idRol FROM rol WHERE nombreRol = :n"), {"n": nombre}
    ).scalar()


def promover(conexion, id_usuario):
    rol_admin = id_rol(conexion, ROL_ADMIN)
    if rol_admin is None:
        raise SystemExit(
            "No existe el rol Administrador; ejecuta primero la migración."
        )
    conexion.execute(
        text("INSERT IGNORE INTO usuario_rol (idUsuario, idRol) VALUES (:u, :r)"),
        {"u": id_usuario, "r": rol_admin},
    )


def main():
    parser = argparse.ArgumentParser(description="Crear o promover administrador.")
    parser.add_argument("correo", help="Correo del administrador")
    parser.add_argument("clave", nargs="?", help="Contraseña (mínimo 8 caracteres)")
    parser.add_argument("usuario", nargs="?", help="Nombre de usuario opcional")
    parser.add_argument("nombre", nargs="?", help="Nombre completo opcional")
    parser.add_argument(
        "--promover", action="store_true",
        help="Solo dar el rol Administrador a un usuario ya registrado",
    )
    args = parser.parse_args()

    correo = args.correo.strip().lower()

    ensure_esquema()

    with engine.begin() as conexion:
        existente = conexion.execute(
            text("""
                SELECT idUsuario, Usuario, NombreCompleto
                FROM usuario WHERE Correo = :c
            """),
            {"c": correo},
        ).mappings().first()

        if args.promover:
            if not existente:
                raise SystemExit(f"No existe ningún usuario con {correo}.")
            promover(conexion, existente["idUsuario"])
            print(
                f"El usuario {existente['Usuario']} "
                f"(id {existente['idUsuario']}) es ahora Administrador."
            )
            return

        if not args.clave:
            raise SystemExit("Falta la contraseña del administrador.")

        if len(args.clave) < 8:
            raise SystemExit("La contraseña debe tener al menos 8 caracteres.")

        if existente:
            promover(conexion, existente["idUsuario"])
            conexion.execute(
                text("""
                    UPDATE usuario
                    SET Clave = :clave,
                        intentosFallidos = 0,
                        fechaBloqueo = NULL
                    WHERE idUsuario = :u
                """),
                {"clave": generate_password_hash(args.clave),
                 "u": existente["idUsuario"]},
            )
            print(
                f"Se restableció la clave y se dio rol Administrador a "
                f"{correo} (id {existente['idUsuario']})."
            )
            return

        usuario = (args.usuario or correo.split("@")[0])[:50]
        nombre = (args.nombre or usuario)[:100]

        resultado = conexion.execute(
            text("""
                INSERT INTO usuario
                    (NombreCompleto, Correo, Usuario, Clave, CorreoVerificado)
                VALUES (:nombre, :correo, :usuario, :clave, TRUE)
            """),
            {
                "nombre": nombre,
                "correo": correo,
                "usuario": usuario,
                "clave": generate_password_hash(args.clave),
            },
        )
        id_nuevo = resultado.lastrowid

        rol_usuario = id_rol(conexion, ROL_USUARIO)
        if rol_usuario:
            conexion.execute(
                text("INSERT IGNORE INTO usuario_rol (idUsuario, idRol) VALUES (:u, :r)"),
                {"u": id_nuevo, "r": rol_usuario},
            )
        promover(conexion, id_nuevo)

        print(
            f"Administrador creado: {correo} / usuario '{usuario}' "
            f"(id {id_nuevo})."
        )


if __name__ == "__main__":
    main()
