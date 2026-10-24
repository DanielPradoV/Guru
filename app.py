
from flask import Flask, render_template

app = Flask(
    __name__,
    template_folder="Vista/paginas",
    static_folder="Vista/static"
)

@app.route("/")
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
