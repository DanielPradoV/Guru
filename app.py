import os
from flask import Flask, render_template, session, redirect, url_for
from controlador.ventas_controlador import ventas_bp

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


app.register_blueprint(ventas_bp)


@app.route("/", methods=["GET", "POST"])
def inicio():
    return render_template("index.html")

@app.route("/principal")
def principal():
    if "id_usuario" not in session:
        return redirect(url_for("inicio"))

    return render_template("principal.html")

@app.route("/productos")
def productos():
    return render_template("productos.html")


@app.route("/carrito")
def carrito():
    return render_template("carrito.html")


@app.route("/nosotros")
def nosotros():
    return render_template("nosotros.html")


if __name__ == "__main__":
    app.run(debug=True)
