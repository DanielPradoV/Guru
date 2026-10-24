
from flask import Flask, render_template
from controlador.ventas_controlador import ventas_bp

app = Flask(
    __name__,
    template_folder="Vista/paginas",
    static_folder="Vista/static"
)

app.register_blueprint(ventas_bp)


@app.route("/", methods=["GET", "POST"])
def inicio():
    return render_template("index.html")


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
