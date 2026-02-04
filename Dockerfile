# Usa l'immagine ufficiale di Python 3.13.7
FROM python:3.13.7-slim

# Aggiorna i pacchetti e installa git
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Crea un utente e un gruppo di sistema
RUN addgroup --system wiwgroup && adduser --system --ingroup wiwgroup wiwuser

# Imposta la directory di lavoro dentro il container
WORKDIR /app

# Copia i file di dipendenze
COPY requirements.txt .

# Installa le dipendenze
RUN pip install --no-cache-dir -r requirements.txt

# Assicura che Python trovi i moduli
ENV PYTHONPATH=/app

# Copia il resto dell'applicazione
COPY . .

# Espone la porta (quella che userai per collegarti)
EXPOSE 8080

# Imposta la variabile d'ambiente per Flask
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8080

# Imposta proprietà file ed utente
RUN chown -R wiwuser:wiwgroup /app
USER wiwuser

# Comando di avvio
CMD ["python", "app.py"]
