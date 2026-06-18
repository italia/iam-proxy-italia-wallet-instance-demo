// --- COMPONENTE ENTRA CON WALLET (RP) ---
if (rpBtn && !rpBtn.hasAddHandler) {
  rpBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    result.innerHTML = ``;
    credPopup.classList.add("show");
    credPopupTitle.innerHTML = "Relying Party";
    // Caricamento asincrono di /itwallet/onboardedRelyingParties e creazione della UI di scelta RP
  });
  rpBtn.hasAddHandler = true;
}

// --- SISTEMA DI SCANSIONE QR (CAMERA) ---
let qrStream = null;
let qrAnimationId = null;
let isQrScanning = false;

function apriQrPopup() {
  const qrModalElement = document.getElementById('qr-scanner-modal');
  const qrModal = new bootstrap.Modal(qrModalElement);
  qrModal.show();
  startQrScanner();
}

async function startQrScanner() {
  const video = document.getElementById("qr-video");
  const canvasElement = document.getElementById("qr-canvas");
  const canvas = canvasElement.getContext("2d", { willReadFrequently: true });
  const textArea = document.getElementById("extra-info");
  const confirmBtn = document.getElementById("confirmLoginRP");

  try {
    qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
    video.srcObject = qrStream;
    video.setAttribute("playsinline", true);
    video.play();
    isQrScanning = true;
    qrAnimationId = requestAnimationFrame(tick);
  } catch (err) {
    console.error("Impossibile accedere alla fotocamera:", err);
    alert("Errore di accesso alla fotocamera. Verifica i permessi.");
    stopQrScanner();
  }

  function tick() {
    if (!isQrScanning) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvasElement.height = video.videoHeight;
      canvasElement.width = video.videoWidth;
      canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
      const imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);

      // jsQR è una dipendenza globale esterna
      const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });

      if (code) {
        textArea.value = code.data;
        if (confirmBtn) confirmBtn.disabled = false;
        const qrModal = bootstrap.Modal.getInstance(document.getElementById('qr-scanner-modal'));
        if (qrModal) qrModal.hide();
        stopQrScanner();
        return;
      }
    }
    qrAnimationId = requestAnimationFrame(tick);
  }
}

function stopQrScanner() {
  isQrScanning = false;
  if (qrAnimationId) { cancelAnimationFrame(qrAnimationId); qrAnimationId = null; }
  if (qrStream) { qrStream.getTracks().forEach(track => track.stop()); qrStream = null; }
  console.log("Scanner QR interrotto.");
}

async function handleQrFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const textArea = document.getElementById("extra-info");
  const confirmBtn = document.getElementById("confirmLoginRP");

  // Crea un lettore di file per trasformare l'immagine in URL Base64
  const reader = new FileReader();
  reader.onload = function(e) {
    const img = new Image();
    img.onload = function() {
      const virtualCanvas = document.createElement("canvas");
      const ctx = virtualCanvas.getContext("2d");
      virtualCanvas.width = img.width;
      virtualCanvas.height = img.height;
      ctx.drawImage(img, 0, 0, img.width, img.height);
      const imageData = ctx.getImageData(0, 0, img.width, img.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
      });

      if (code) {
        console.log("QR Code rilevato da file:", code.data);
        const input_body = {
          qrcode_data: code.data
        };
        try {
          const response = await executeFetch("/wallet/presentation", "POST", input_body);
          if (!response.ok)
            throw new Error(await getErrorMessage(response));
          const qrModalElement = document.getElementById('qr-scanner-modal');
          const qrModal = bootstrap.Modal.getInstance(qrModalElement);
          if (qrModal) qrModal.hide();
          stopQrScanner();
        } catch (err) {
          console.error(err);
        }
      } else {
        alert("Impossibile trovare un QR Code valido in questa immagine. Riprova con un'immagine più nitida.");
      }

      event.target.value = "";
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}