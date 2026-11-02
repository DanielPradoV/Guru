# Guru

Aplicación Flask + MariaDB/MySQL con autenticación por sesión en base de
datos, roles y permisos, auditoría, recuperación de contraseña y panel de
métricas de uso.

## Ejecutar

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
python app.py
```

El esquema (tablas de roles, permisos, auditoría, archivos y visitas) se
crea o completa automáticamente al arrancar la aplicación, porque el
despliegue en Render no dispone de shell para correr migraciones a mano.

## Variables de entorno

| Variable | Uso | Valor por defecto |
| --- | --- | --- |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | conexión a MariaDB/MySQL | localhost / guru |
| `SECRET_KEY` | firma de la cookie de sesión | — |
| `SESSION_TIMEOUT_MINUTES` | inactividad antes de cerrar la sesión | 30 |
| `RESET_TOKEN_MINUTES` | validez del token de "Olvidé mi contraseña" | 30 |
| `VERIFICACION_TOKEN_MINUTES` | validez del token de verificación de correo | 30 |
| `LOCK_MAX_INTENTOS`, `LOCK_MINUTES` | bloqueo de cuenta tras intentos fallidos | 5 / 15 |
| `MAX_UPLOAD_BYTES` | tamaño máximo de archivo subido | 5 MB |
| `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `APP_BASE_URL` | envío de correos | — |

## Usuario administrador

Se crea o se promueve desde la línea de comandos:

```bash
python scripts/crear_admin.py admin@guru.com "ClaveSegura12" admin "Administrador Guru"
python scripts/crear_admin.py --promover danielverano016@gmail.com   # rol Admin a un usuario existente
```

Si el correo ya existe, el script restablece su contraseña y le asigna el
rol `Administrador`. En Render hay que ejecutar el mismo comando desde el
Root Shell del servicio, o registrar el correo desde `/registro` y luego
promoverlo desde **Panel → Usuarios** marcando la casilla del rol.

## Métricas de uso

`/admin/estadisticas` (permiso `ver_auditoria`) muestra una gráfica de
Chart.js con las personas que entraron por día y los minutos promedio de
permanencia, además del ranking por usuario y las últimas visitas.

Los datos vienen de la tabla `visita`: cada inicio de sesión abre una fila
y cada petición del usuario (incluido el latido cada 60 s que envía la
página principal mientras la pestaña está abierta) actualiza `fechaFin`.
La permanencia de una visita es, por tanto, `fechaFin − fechaInicio`.
