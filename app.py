import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, session, redirect, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from controlador.ventas_controlador import ventas_bp
from controlador.admin_controlador import admin_bp
from controlador.cuenta_controlador import cuenta_bp
from controlador.seguridad import (
    minutos_sesion,
    obtener_permisos,
    sesion_timeout,
)

app = Flask(
    __name__,
    template_folder="Vista/paginas",
    static_folder="Vista/static"
)

app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "Falta configurar la variable de entorno SECRET_KEY."
    )

# Render/los proxies terminan TLS antes de la app: sin esto los enlaces
# de correo se generan con http y con el host interno en vez del dominio.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Cookie de sesión con expiración configurable y ventana deslizante:
# se renueva en cada petición activa hasta el valor que defina el
# administrador en /admin/configuracion.
app.permanent_session_lifetime = sesion_timeout()

# Límite de tamaño para la subida de archivos (punto 15).
app.config["MAX_CONTENT_LENGTH"] = int(
    os.getenv("MAX_UPLOAD_BYTES", 5 * 1024 * 1024)
)

# Logs de la aplicación también a archivo para poder auditar fallos
# (los registros de auditoría de negocio viven en la tabla auditoria).
_log_dir = os.path.join(app.root_path, "logs")
os.makedirs(_log_dir, exist_ok=True)
_handler = RotatingFileHandler(
    os.path.join(_log_dir, "aplicacion.log"),
    maxBytes=1_000_000,
    backupCount=5,
    encoding="utf-8",
)
_handler.setFormatter(logging.Formatter(
    "%(asctime)s %(levelname)s en %(name)s: %(message)s [en %(pathname)s:%(lineno)d]"
))
_handler.setLevel(logging.INFO)
app.logger.addHandler(_handler)
app.logger.setLevel(logging.INFO)

# El esquema de la base de datos se asegura al arrancar: es una migración
# aditiva e idempotente, necesaria en despliegues donde no hay shell.
try:
    from modelo.migraciones import ensure_esquema
    ensure_esquema()
except Exception:
    app.logger.exception(
        "No se pudo aplicar la migración del esquema al arrancar"
    )

app.register_blueprint(ventas_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(cuenta_bp)


@app.route("/", methods=["GET", "POST"])
def inicio():
    return render_template("index.html")

@app.route("/principal")
def principal():
    if "id_usuario" not in session:
        return redirect(url_for("inicio"))

    permisos = obtener_permisos(session["id_usuario"])

    return render_template(
        "principal.html",
        permisos=permisos,
        session_timeout_minutes=minutos_sesion(),
    )

@app.route("/productos")
def productos():
    return render_template("productos.html")


@app.route("/carrito")
def carrito():
    return render_template("carrito.html")


@app.route("/nosotros")
def nosotros():
    return render_template("nosotros.html")


@app.errorhandler(413)
def archivo_demasiado_grande(error):
    return render_template(
        "mensaje.html",
        mensaje="El archivo supera el tamaño máximo permitido (5 MB).",
        tipo_mensaje="error",
    ), 413


if __name__ == "__main__":
    app.run(debug=True)
