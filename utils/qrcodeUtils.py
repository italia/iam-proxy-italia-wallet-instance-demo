import os
import ctypes

# Ora importa pyzbar
from pyzbar.pyzbar import decode
from PIL import Image

# Carica e decodifica immagine
image = Image.open("download.png")
results = decode(image)

# Stampa il risultato
for result in results:
    print("QR Code:", result.data.decode())


