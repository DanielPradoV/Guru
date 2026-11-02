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
| `SESSION_TIMEOUT_MINUTES` | respaldo del tiempo de inactividad de la sesión (luego manda la BD) | 30 |
| `RESET_TOKEN_MINUTES` | respaldo de la validez de los tokens de autenticación | 30 |
| `LOCK_MAX_INTENTOS`, `LOCK_MINUTES` | bloqueo de cuenta tras intentos fallidos | 5 / 15 |
| `MAX_UPLOAD_BYTES` | tamaño máximo de archivo subido | 5 MB |
| `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `APP_BASE_URL` | envío de correos | — |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | administrador que se siembra al arrancar | desactivado |
| `ADMIN_USUARIO`, `ADMIN_NOMBRE` | datos opcionales de ese administrador | derivados del correo |

## Usuario administrador

En **Render** (sin shell) define en *Environment* `ADMIN_EMAIL` y
`ADMIN_PASSWORD` y hace un redeploy: al arrancar, la aplicación crea ese
usuario con el rol `Administrador` si no existe. Si el correo ya estaba
registrado, solo se le asegura el rol y **nunca** se le cambia la
contraseña, para no deshacer un cambio hecho desde el panel.

Desde la línea de comandos, en cualquier entorno:

```bash
python scripts/crear_admin.py admin@guru.com "ClaveSegura12" admin "Administrador Guru"
python scripts/crear_admin.py --promover danielverano016@gmail.com   # rol Admin a un usuario existente
```

Si el correo ya existe, el script restablece su contraseña y le asigna el
rol `Administrador`. Alternativa sin terminal: registrar el correo desde
`/registro` y luego promoverlo desde **Panel → Usuarios** marcando la
casilla del rol.

## Tiempos de expiración editables

`/admin/configuracion` (permiso `gestionar_configuracion`) deja ajustar sin
redeployar los dos tiempos que se evalúan en los puntos 10 y 11 del
checklist. Se guardan en la tabla `configuracion_seguridad` y la aplicación
los lee en cada uso, así que el cambio toma efecto en la misma petición:

- `sesion_minutos` — inactividad antes de cerrar la sesión de la app. Al
  guardarlo, las sesiones vivas pasan a la ventana nueva.
- `token_minutos` — validez de los enlaces de verificación de correo y de
  restablecimiento de contraseña. Al **reducirlo**, los enlaces ya emitidos
  se recortan a la ventana nueva.

Los valores de entorno son solo el respaldo mientras la tabla no exista.
Cada guardado se registra en auditoría con la acción
`cambio_configuracion`.

## Métricas de uso

`/admin/estadisticas` (permiso `ver_auditoria`) muestra una gráfica de
Chart.js con las personas que entraron por día y los minutos promedio de
permanencia, además del ranking por usuario y las últimas visitas.

Los datos vienen de la tabla `visita`: cada inicio de sesión abre una fila
y cada petición del usuario (incluido el latido cada 60 s que envía la
página principal mientras la pestaña está abierta) actualiza `fechaFin`.
La permanencia de una visita es, por tanto, `fechaFin − fechaInicio`.
