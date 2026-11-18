# Control de Entrega de Unidades — versión local 1.0

Aplicación web independiente de IntegraStock, con API REST, diseño móvil, base SQLite y generación de PDF con hasta 6 fotografías por hoja. **No está desplegada ni conectada a datos de Contemar o a IntegraStock.**

## Requisitos

- Python 3.10 o superior.
- Instalar dependencias: `python -m pip install -r requirements.txt`

## Iniciar en Windows (PowerShell)

```powershell
cd "RUTA\control-entregas-unidades"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:UNIDADES_ADMIN_PASSWORD = "CAMBIA_ESTA_CLAVE_POR_UNA_SEGURA_2026!"
uvicorn app:app --host 127.0.0.1 --port 8000
```

Abrir http://127.0.0.1:8000 . Usuario inicial: `admin`. Contraseña: la que configures en la variable de entorno. Recomendación: reemplazar el ejemplo con una clave propia de al menos 12 caracteres. La variable solo se usa para crear el primer usuario; si ya existe una base de datos, **cambiar la variable no modifica su contraseña**.

En macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export UNIDADES_ADMIN_PASSWORD='UNA_CLAVE_PROPÍA_MUY_SEGURA'
uvicorn app:app --host 127.0.0.1 --port 8000
```

### Uso de la aplicación

1. **Tipos y plantillas:** define cada código de unidad y cuáles controles aplican. Los valores N/A predeterminados se copian al crear unidades nuevas. La plantilla se puede personalizar sin modificar unidades existentes.
2. **Responsables / QR:** crea trabajadores que ENTREGAN y jefes/supervisores que RECIBEN. Asocia el valor exacto que contienen sus QR (para el escáner) y adjunta la **imagen individual** correspondiente (para el PDF). El contenido QR se puede recuperar con un lector QR externo o una herramienta confiable; no inventes valores. Los QR de las capturas adjuntas se incluyen como recortes de referencia en `referencias_qr/` y se deben confirmar visualmente antes de asignarlos.
3. **Nueva unidad:** elige `Arriendo`, `Stock` o `NV`; ingresa código propio, tipo, número de NV opcional y observaciones. Una unidad recién guardada queda **amarilla**.
4. **Revisión:** elige V°B°, N/A o Pendiente en cada control. Al iniciar queda **roja**, aunque llegue a 100% si aún no se confirma la recepción.
5. **Fotos:** adjunta desde cámara/galería, agrega descripciones y guarda todos los cambios. Permite retomar el informe al día siguiente.
6. **Recepción:** identifica trabajador y supervisor (selección o escaneo), resuelve todos los controles aplicables y confirma la recepción por usuario autenticado. Queda **verde** y bloqueado para ediciones.
7. **Historial y PDF:** busca por código, tipo, detalle o NV. Abre el PDF para imprimir o guardar. Si no ha terminado se indica `DOCUMENTO PRELIMINAR`. El anexo fotográfico usa 2 columnas × 3 filas por hoja.

### Seguridad y limitaciones de la primera versión

- Se ejecuta **solo en localhost**. No exponer a Internet ni a una red corporativa sin HTTPS, controles adicionales y revisión de seguridad.
- El primer usuario es un administrador local; no hay aún alta de múltiples cuentas, recuperación de contraseña, permisos finos, firmas electrónicas, almacenamiento de objetos ni sincronización multiusuario. Las sesiones son en memoria: se invalidan al reiniciar el servicio.
- El QR identifica un registro y su lectura **no prueba** la identidad física ni equivale a una firma. Solo la sesión autenticada confirma la recepción; el nombre del supervisor es un responsable asociado, no una prueba de que esa persona inició sesión. Para producción: autenticación individual, MFA, autorización por roles, bitácora inmutable y validación presencial de entrega.
- SQLite es adecuado para prueba local y uso sencillo; en producción multiempresa se migraría a PostgreSQL/Supabase con `tenant_id`, RLS y almacenamiento privado de fotos.
- La fecha y hora son registradas por servidor en UTC; pueden mostrarse con la zona local al integrar. No se editan las fechas de creación o cierre.
- Los códigos de tipos iniciales se transcribieron de manera orientativa desde capturas de baja resolución: **verificarlos antes de uso real**; se pueden crear otros tipos en el catálogo.
- Todos los informes cerrados son inmutables desde la interfaz. Para correcciones oficiales posteriores debería añadirse un mecanismo de nueva revisión/versionado, no sobrescribir evidencia.
- Fotos hasta 8 MB por imagen, 100 por unidad; ingreso JPEG, PNG, etc. convertido a JPEG con metadatos EXIF eliminados.

## Organización

- `app.py`: API, reglas del negocio, persistencia y PDF.
- `static/`: interfaz web responsive sin dependencias front-end de CDN.
- `data/units.sqlite3`: base de datos creada al arrancar; `data/photos/` y `data/qr/`: evidencias privadas.
- `referencias_qr/`: recortes de QR suministrados para facilitar asignación **solo previa validación**. No se leen automáticamente ni se asignan a ningún nombre.

### Copias de seguridad

Detener la aplicación y guardar la carpeta `data/` completa en un sitio seguro. No se recomienda subir esa carpeta al repositorio Git ni enviar imágenes QR de personas a un repositorio público.

## Integración futura con IntegraStock

Mantener el módulo aislado y migrar por fases:

1. Mapear `units` a `delivery_inspections`, `reviews` a `delivery_inspection_items`, `photos` a archivos privados de Supabase Storage, `people` a responsables organizacionales (sin conceder acceso a partir de un QR).
2. Añadir `tenant_id` y referencias opcionales a unidad real, notas de venta y órdenes de producción de IntegraStock. Mantener código visible e identificador interno por separado.
3. Aplicar RLS por empresa, permisos `delivery.view/create/review/receive/manage_templates` y auditoría de quién **realmente** autentica la recepción.
4. Permitir importar tipos/plantillas, conservar PDFs históricos y generar PDFs nuevos desde una función protegida.
5. Repetir pruebas antes de integrarlo, en una rama separada; **no tocar main, Supabase remoto ni desplegar Vercel** sin autorización.

## Ejecutar pruebas

```bash
python -m unittest discover -s tests -v
```
