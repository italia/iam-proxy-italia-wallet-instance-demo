if (rpBtn && !rpBtn.hasAddHandler) {
  rpBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    if (result) result.innerHTML = ``;
    credPopup.classList.add("show");
    credPopupTitle.innerHTML = "Relying Party";
  });
  rpBtn.hasAddHandler = true;
}

let qrStream = null;
let qrAnimationId = null;
let isQrScanning = false;

function apriQrPopup() {
  const qrModalElement = document.getElementById('qr-scanner-modal');
  if (!qrModalElement) return;
  const qrModal = new bootstrap.Modal(qrModalElement);
  qrModal.show();
  startQrScanner();
}

async function startQrScanner() {
  const video = document.getElementById("qr-video");
  const canvasElement = document.getElementById("qr-canvas");
  if (!video || !canvasElement) return;

  const canvas = canvasElement.getContext("2d", { willReadFrequently: true });

  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert("Fotocamera non supportata o contesto non sicuro (richiede HTTPS o localhost).");
    stopQrScanner();
    return;
  }

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

      const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });

      if (code) {
        processQrPresentation(code.data);
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

function handleQrFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function(e) {
    const img = new Image();
    img.onload = async function() {
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
        await processQrPresentation(code.data);
      } else {
        alert("Impossibile trovare un QR Code valido in questa immagine. Riprova con un'immagine più nitida.");
      }

      event.target.value = "";
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

async function processQrPresentation(qrData) {
  try {
    const response = await executeFetch("/wallet/presentation", "POST", { qrcode_data: qrData });
    if (!response.ok) {
      throw new Error(await getErrorMessage(response));
    }

    response_json = await response.json();

//    @TODO UPDATE MODAL
    let frase = "";

    credentialsPresenting = response_json.data;

      if (Array.isArray(credentialsPresenting)) {
        if (credentialsPresenting.length === 0) {
          frase = `<p>Per la login con il Relying Party selezionato, non sarà condiviso alcun dato.</p>`;
        } else {
          // Costruiamo i <li> con credenziali e claims
          const descrizioni = credentialsPresenting.map(cred => {
            const nome = `<b>${cred.id}</b> in ${cred.format}`;

            const claimsPaths = (cred.claims || [])
              .map(c => c.path?.join("."))
              .filter(Boolean);

            // Se ci sono claims, creo una sottolista <ul> con <li> singoli
            const claimsList = claimsPaths.length > 0
              ? `<ul>` + claimsPaths.map(path => `<li>${path}</li>`).join("") + `</ul>`
              : "";

            return `<li>${nome}${claimsList}</li>`;
          });

          frase = `
            <p>Per la login con il Relying Party selezionato, saranno condivisi i seguenti dati:</p>
            <ul style="margin-top: 0px">${descrizioni.join("")}</ul>
            <p>Premendo Continua autorizzi la trasmissione delle informazioni.</p>
          `;
        }

        credPopupBody.innerHTML = `
          <div class="custom-confirm-wrapper">
            <div class="confirm-text">${frase}</div>
            <div class="button-wrapper">
              <button id="continuePresentCredential" class="popup-btn confirm" onclick="loginContinueCredPopup()">Continua</button>
              <button id="cancelPresentCredential" class="popup-btn cancel" onclick="closeCredPopup()">Annulla</button>
            </div>
          </div>`;
      } else {
        console.error("credentials non è un array!", credentialsPresenting);
        credPopupBody.innerHTML = `
          <div class="flash-container flash-error">
            <p>Credentials non è un array!</p>
          </div>`;
      }

//    @TODO UPDATE MODAL

    const qrModalElement = document.getElementById('qr-scanner-modal');
    if (qrModalElement) {
      const qrModal = bootstrap.Modal.getInstance(qrModalElement);
      if (qrModal) qrModal.hide();
    }
    stopQrScanner();

    const presentationModalComponent = document.getElementById('presentation-modal');
    if (presentationModal) {
      const presentationModal = bootstrap.Modal.getInstance(presentationModalComponent);
      if (presentationModal) presentationModal.show();
    }

  } catch (err) {
    console.error("Errore durante la presentazione del wallet:", err);
    alert("Errore nell'invio dei dati al backend: " + err.message);
  }
}