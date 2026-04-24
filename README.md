# HamActivity Bridge

Pasarela de escritorio escrita en Python/Tkinter que toma QSOs enviados por
N1MM vía UDP y los publica en la API pública de HamActivity.

## Requisitos

- Python 3.12+
- Dependencias Python: `requests`.
- Sistema operativo: Windows, macOS o Linux (Tkinter estándar).

## Instalación rápida

```bash
python -m venv .venv
.venv\Scripts\activate      # En Windows (PowerShell)
# o bien
source .venv/bin/activate   # En macOS/Linux

pip install -r requirements.txt  # si existe
pip install requests
```

*Nota*: Tkinter viene incluido en las instalaciones estándar de Python para
Windows/macOS. Si usas distribuciones minimalistas verifica que el paquete
`tk` esté presente.

## Ejecución

```bash
python radioaward_bridge.py
```

La aplicación guardará la URL base, API key, perfil de log y puerto UDP en
`~/.hamactivity_bridge_settings.json`.

### Flujo básico

1. Introduce la URL base de la API, tu API key y mueve el puerto UDP si es
   necesario (por defecto 9091).
2. Pulsa “Guardar”.
3. Presiona “Login” para validar la API key; usa el combo “Diploma” para elegir
   el diplomas activo.
4. Mantén el listener UDP activo (por defecto ya queda escuchando); N1MM debe
   emitir datagramas hacia esa IP/puerto.
5. Revisa el panel “Registro” para ver el detalle de cada envío. Activa la
   casilla “Debug” si deseas ver los JSON completos.

## Builds automáticos (GitHub Actions)

Este repo incluye cuatro workflows que se ejecutan al publicar una release o de
forma manual desde Actions. Tres empaquetan la app con PyInstaller y uno genera
la guía de instalación en PDF; todos suben sus artefactos como assets de la
release:

1. **Build Windows Binary** (`.github/workflows/build-windows.yml`):
   - Se ejecuta automáticamente al publicar una release y también se puede
     lanzar manualmente desde Actions (opcionalmente indicando un tag).
   - Corre en `windows-latest`, instala Python 3.12, `requests` y `pyinstaller`.
   - Hace checkout del tag de esa release y genera
     `dist/hamactivity_bridge-win-<tag>.zip` (contiene el .exe).
   - Sube el ZIP como asset a la release publicada.

2. **Build macOS Binary** (`.github/workflows/build-macos.yml`):
   - Se ejecuta automáticamente al publicar una release y también admite
     ejecución manual con el tag deseado.
   - Corre en `macos-latest` con los mismos pasos (PyInstaller + compresión).
   - Usa el tag de la release para compilar y publica
     `dist/hamactivity_bridge-macos-<tag>.dmg` como asset en la release.

3. **Build Linux Binary** (`.github/workflows/build-linux.yml`):
   - Se ejecuta automáticamente al publicar una release y también admite
     ejecución manual con el tag deseado.
   - Corre en `ubuntu-latest`, instala Python 3.12, `python3-tk`, `requests`
     y `pyinstaller`.
   - Usa el tag de la release para compilar y publica
     `dist/hamactivity_bridge-linux-<tag>.tar.gz` como asset en la release.

4. **Build Installation PDF** (`.github/workflows/build-install-pdf.yml`):
   - Se ejecuta automáticamente al publicar una release y también admite
     ejecución manual con el tag deseado.
   - Corre en `ubuntu-latest`, instala `pandoc` y `wkhtmltopdf`.
   - Convierte `INSTALL-WINDOWS.md` e `INSTALL-MAC.md` en
     `dist/hamactivity_bridge-install-windows-<tag>.pdf` y
     `dist/hamactivity_bridge-install-macos-<tag>.pdf`, incluyendo las imágenes
     de cada documento.
   - Sube el PDF como artefacto del workflow y también como asset en la release.

Tras ejecutar cualquiera de los workflows podrás descargar los artefactos
generados desde la propia página de la release correspondiente.

## Tests

Actualmente no hay suite de tests automatizada. Para validaciones básicas:

```bash
python -m py_compile radioaward_bridge.py
```

### Próximos pasos sugeridos

- Añadir un `requirements.txt` o `poetry.lock` para fijar dependencias.
- Incorporar pruebas unitarias para las transformaciones de payload.
- Añadir más perfiles de “Log” si se soportan otros programas además de N1MM.
