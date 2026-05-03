# Usa una imagen oficial de Python ligera basada en Debian
FROM python:3.11-slim

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Variables de entorno para optimizar Python
# PYTHONDONTWRITEBYTECODE: Evita que se escriban archivos .pyc en disco
# PYTHONUNBUFFERED: Asegura que los logs lleguen a la terminal en tiempo real
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Instala dependencias del sistema necesarias (gcc y libpq son para drivers de Postgres)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copia el archivo de requerimientos primero para aprovechar la caché de capas de Docker
COPY app/requirements.txt .

# Instala las librerías de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo el contenido del directorio actual al directorio de trabajo en el contenedor
COPY app/ .

# Expone el puerto 8000 (puerto por defecto de FastAPI/Uvicorn)
EXPOSE 8000

# Comando para iniciar la aplicación
# --host 0.0.0.0 es obligatorio para que el contenedor sea accesible desde fuera
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]