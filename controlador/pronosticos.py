"""Pronósticos de series diarias: Media Móvil Simple (SMA) y
Suavizado Exponencial Simple (SES).

Funciones puras, sin dependencias externas. Cada método devuelve:
    ajuste     -> predicción de un paso adelante para cada punto histórico
                  (None donde todavía no hay datos suficientes).
    pronostico -> valores estimados para los próximos `horizonte` días.
"""
from math import sqrt


def media_movil_simple(serie, ventana, horizonte):
    """SMA: cada predicción es el promedio de los últimos `ventana` valores.

    Para el futuro se aplica de forma recursiva: cada día pronosticado
    entra en la ventana del siguiente.
    """
    n = len(serie)
    if ventana < 1 or n < ventana:
        raise ValueError("La ventana debe ser >= 1 y no mayor que la serie")

    ajuste = [None] * n
    for t in range(ventana, n):
        ajuste[t] = sum(serie[t - ventana:t]) / ventana

    historial = list(serie)
    pronostico = []
    for _ in range(horizonte):
        siguiente = sum(historial[-ventana:]) / ventana
        pronostico.append(siguiente)
        historial.append(siguiente)

    return ajuste, pronostico


def suavizado_exponencial_simple(serie, alpha, horizonte):
    """SES: nivel_t = alpha * y_t + (1 - alpha) * nivel_(t-1).

    El nivel se inicializa con el primer dato. El pronóstico a cualquier
    horizonte es el último nivel (línea plana), porque SES no modela
    tendencia ni estacionalidad.
    """
    if not serie:
        raise ValueError("La serie no puede estar vacía")
    if not 0 < alpha <= 1:
        raise ValueError("alpha debe estar en (0, 1]")

    nivel = serie[0]
    ajuste = [None]
    for y in serie[1:]:
        ajuste.append(nivel)
        nivel = alpha * y + (1 - alpha) * nivel

    return ajuste, [nivel] * horizonte


def errores(serie, ajuste, desde=0):
    """MAE y RMSE de las predicciones de un paso desde el índice `desde`."""
    residuos = [
        serie[t] - ajuste[t]
        for t in range(desde, len(serie))
        if ajuste[t] is not None
    ]
    if not residuos:
        return None, None
    mae = sum(abs(r) for r in residuos) / len(residuos)
    rmse = sqrt(sum(r * r for r in residuos) / len(residuos))
    return mae, rmse


def pronosticar_ingresos(serie, ventana=3, alpha=0.3, horizonte=7):
    """Calcula SMA y SES sobre la misma serie y sus errores comparables.

    Los errores se miden sobre el mismo tramo (desde `ventana`) para que
    los dos métodos se puedan comparar de forma justa.
    """
    ajuste_sma, pron_sma = media_movil_simple(serie, ventana, horizonte)
    ajuste_ses, pron_ses = suavizado_exponencial_simple(
        serie, alpha, horizonte
    )

    mae_sma, rmse_sma = errores(serie, ajuste_sma, ventana)
    mae_ses, rmse_ses = errores(serie, ajuste_ses, ventana)

    def redondear(valores):
        return [None if v is None else round(v, 2) for v in valores]

    return {
        "sma": {
            "ajuste": redondear(ajuste_sma),
            "pronostico": redondear(pron_sma),
            "mae": None if mae_sma is None else round(mae_sma, 2),
            "rmse": None if rmse_sma is None else round(rmse_sma, 2),
        },
        "ses": {
            "ajuste": redondear(ajuste_ses),
            "pronostico": redondear(pron_ses),
            "mae": None if mae_ses is None else round(mae_ses, 2),
            "rmse": None if rmse_ses is None else round(rmse_ses, 2),
        },
        "ventana": ventana,
        "alpha": alpha,
        "horizonte": horizonte,
    }
