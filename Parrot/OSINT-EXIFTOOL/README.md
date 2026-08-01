# 🔍 Práctica OSINT — Extracción de Metadatos con ExifTool

Análisis de metadatos de una imagen mediante **ExifTool** sobre **Parrot OS**, como ejercicio práctico de OSINT (Open Source Intelligence) y análisis forense de archivos.

**Autor:** Víctor Bastidas
**Fecha:** Julio 2026
**Sistema:** Parrot OS · **Herramienta:** ExifTool v13.25

---

## 📖 Descripción

Este repositorio documenta una práctica de recolección de información en la que se emplea ExifTool para inspeccionar los metadatos incrustados en un archivo de imagen. El objetivo es comprender qué información puede extraer un analista OSINT de un fichero y cuáles son las implicaciones de privacidad asociadas.

---

## 📂 Contenido del repositorio

| Archivo | Descripción |
|---------|-------------|
| `README.md` | Este documento |
| `INFORME_OSINT_EXIFTOOL.md` | Informe completo de la práctica |

---

## 🛠️ Herramienta utilizada

**ExifTool** — utilidad de línea de comandos para leer, escribir y editar metadatos en múltiples formatos de archivo. Es una referencia en el análisis OSINT de imágenes y documentos.

---

## ⚙️ Reproducir la práctica

### 1. Instalación en Parrot OS / Debian

```bash
sudo apt install exiftool
```

> El paquete real es `libimage-exiftool-perl`, que APT resuelve automáticamente.

### 2. Verificar la instalación

```bash
exiftool
```

### 3. Analizar un archivo

```bash
exiftool imagen.png
```

---

## 📊 Resultado destacado

El análisis de la imagen de prueba (formato PNG) mostró propiedades técnicas (dimensiones, profundidad de color, marcas temporales) pero **no** contenía datos EXIF de cámara ni coordenadas GPS. Esto ilustra que los archivos PNG suelen exponer mucha menos información identificable que los JPEG provenientes de dispositivos móviles.

Consulta el [informe completo](./INFORME_OSINT_EXIFTOOL.md) para el detalle de todos los metadatos y el análisis.

---

## 🔒 Contramedida rápida

Para eliminar todos los metadatos de un archivo antes de compartirlo:

```bash
exiftool -all= imagen.jpg
```

---

## 📌 Nota

Este material se elabora con fines exclusivamente **académicos y de formación en ciberseguridad**. El análisis OSINT debe realizarse siempre sobre archivos y objetivos para los que se cuente con autorización.

---

⭐ Si te resultó útil, no dudes en dejar una estrella al repositorio.
