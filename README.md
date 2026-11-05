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
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | envío de correos por SMTP directo | `smtp.gmail.com` / `587` / — |
| `RESEND_API_KEY`, `RESEND_FROM_EMAIL` | envío de correos por Resend (respaldo) | — |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | administrador que se siembra al arrancar | desactivado |
| `ADMIN_USUARIO`, `ADMIN_NOMBRE` | datos opcionales de ese administrador | derivados del correo |

## Envío de correos

`controlador/correo.py` decide el proveedor con las variables de entorno y
es el único punto que habla con el exterior; las rutas de verificación y de
recuperación solo le piden `enviar(destinatario, asunto, html)`.

- Con `SMTP_USER` **y** `SMTP_PASSWORD` definidos, envía por SMTP directo
  (`smtplib`, sin dependencias externas) y entrega a cualquier dirección.
  Para Gmail hay que activar la verificación en dos pasos y generar una
  [contraseña de aplicación](https://myaccount.google.com/apppasswords);
  el remitente es esa misma cuenta (`SMTP_FROM` solo añade nombre visible).
- Si no, usa `RESEND_API_KEY`. En la cuenta de pruebas de Resend solo
  entrega al correo con el que te registraste.
- Si no hay ninguno, `enviar` lanza excepción y la ruta muestra el aviso de
  "no se pudo enviar"; el token se revierte junto con la transacción, así
  que no quedan enlaces vivos de un correo que nunca salió.

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

Los valores de entorno son solo el respaldo mientras la tabla no exista:
se usan cuando la tabla todavía no se ha creado (el arranque necesita el
tiempo de sesión antes de que corra la migración) o cuando la base de datos
no responde. Cada guardado se registra en auditoría con la acción
`cambio_configuracion`.

## Decisiones de diseño

### Sesión y autenticación

- Una cuenta solo puede tener **una sesión activa** (`sesion_usuario`); el
  segundo inicio es rechazado hasta que se cierre la primera.
- Antes de buscar la sesión activa se depuran las filas caducadas y las que
  nacieron sin `fechaExpiracion` (heredadas de versiones anteriores a la
  migración): sin fecha nunca vencerían y bloquearían el acceso del usuario.
- La expiración es una **ventana deslizante**: cada petición válida mueve
  `fechaUltimaActividad` y `fechaExpiracion`. La página principal manda un
  latido a `/keepalive` cada 60 s mientras la pestaña está abierta, así que
  una sesión no se corta por inactividad falsa, pero sí vence si nadie la
  usa. La cookie de Flask (`session.permanent`) sigue el mismo criterio y su
  tiempo de vida se recalcula por petición, para que el panel surta efecto
  sin reiniciar el servidor.
- Cambiar la contraseña —desde el perfil o desde el panel de Usuarios— cierra
  **todas** las sesiones activas de esa cuenta.

### Correos y despliegue detrás de proxy

- Render termina TLS antes de llegar a la app, por eso se aplica `ProxyFix`:
  sin él los enlaces se generan con `http` y con el host interno. Con
  ProxyFix puesto, `url_for(..., _external=True)` produce la URL pública
  correcta, así que no existe una variable de "URL base".
- El correo se envía **antes** de confirmar la transacción; si el envío
  falla, el token se revierte con todo lo demás.
- La recuperación de contraseña responde siempre el mismo mensaje: no se
  revela si el correo existe o no en la base de datos.

### Auditoría y logs

- `registrar_accion()` se llama **fuera** de la transacción de negocio. La
  clave foránea de `auditoria` sobre `usuario` esperaría el lock que esa
  misma transacción sostiene y provocaría un deadlock.
- Los fallos técnicos se escriben además en `logs/aplicacion.log`; los
  registros de auditoría de negocio viven solo en la tabla `auditoria`.

### Roles y permisos

- El rol `Administrador` recibe todos los permisos **solo al crearse**;
  después se administra desde el panel.
- Los permisos que estrena una migración se conceden al `Administrador` una
  sola vez (los recién creados). Así, un permiso retirado a mano desde el
  panel de Roles sigue retirado después de un relanzamiento.
- El primer usuario registrado queda como administrador para que el panel
  sea alcanzable; se puede reasignar desde la interfaz.
- Al crear o editar un usuario desde el panel también se le exige la
  complejidad de contraseña: un administrador no puede imponer una clave débil.

### Subida de archivos

- `MAX_CONTENT_LENGTH` limita el cuerpo de la petición al valor de
  `MAX_UPLOAD_BYTES`.
- Se valida la firma binaria real (*magic bytes*), no la extensión: un
  `.exe` renombrado como `.pdf` se rechaza. WEBP se confirma en el
  desplazamiento 8 de la cabecera.
- El nombre del archivo en disco lo genera el servidor; el nombre enviado
  por el cliente nunca se usa como ruta.

### Base de datos

- El esquema se asegura al arrancar con una migración aditiva e idempotente,
  porque el despliegue en Render no dispone de shell.
- Todas las fechas se guardan en `DATETIME` escritas con `UTC_TIMESTAMP()`,
  nunca con la hora local del servidor.
- SSL solo se activa cuando el host de la base de datos no es local.

## Métricas de uso

`/admin/estadisticas` (permiso `ver_auditoria`) muestra una gráfica de
Chart.js con las personas que entraron por día y los minutos promedio de
permanencia, además del ranking por usuario y las últimas visitas.

Los datos vienen de la tabla `visita`: cada inicio de sesión abre una fila
y cada petición del usuario (incluido el latido cada 60 s que envía la
página principal mientras la pestaña está abierta) actualiza `fechaFin`.
La permanencia de una visita es, por tanto, `fechaFin − fechaInicio`.
