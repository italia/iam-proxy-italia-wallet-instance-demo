let qrStream = null;
let qrAnimationId = null;
let isQrScanning = false;
let qrMode = "camera";
let qrCrop = null;

function openQrPopup() {
  const qrModalElement = document.getElementById("qr-scanner-modal");
  if (!qrModalElement) return;
  const qrModal = new bootstrap.Modal(qrModalElement);
  qrModal.show();
  startQrScanner();
}

function closeQrPopup() {
  const qrModalElement = document.getElementById("qr-scanner-modal");
  if (qrModalElement) {
    const qrModal = bootstrap.Modal.getInstance(qrModalElement);
    if (qrModal) qrModal.hide();
  }
  stopQrScanner();
}

function setQrHint(message) {
  const hint = document.getElementById("qr-hint");
  if (!hint) return;
  if (!hint.dataset.default) hint.dataset.default = hint.textContent;
  hint.textContent = message || hint.dataset.default;
}

function showQrSelection(box) {
  const selection = document.getElementById("qr-selection");
  if (!selection) return;
  if (!box) {
    selection.hidden = true;
    return;
  }
  selection.hidden = false;
  selection.style.left = `${box.x}px`;
  selection.style.top = `${box.y}px`;
  selection.style.width = `${box.w}px`;
  selection.style.height = `${box.h}px`;
}

function cssPoint(event, stage) {
  const rect = stage.getBoundingClientRect();
  return { x: event.clientX - rect.left, y: event.clientY - rect.top };
}

function boxFromPoints(start, end) {
  const x = Math.min(start.x, end.x);
  const y = Math.min(start.y, end.y);
  return { x, y, w: Math.abs(end.x - start.x), h: Math.abs(end.y - start.y) };
}

function toBitmap(box, canvas, stage) {
  const rect = canvas.getBoundingClientRect();
  const stageRect = stage.getBoundingClientRect();
  if (!rect.width || !rect.height || !canvas.width || !canvas.height) return null;
  const scaleX = canvas.width / rect.width;
  const scaleY = canvas.height / rect.height;
  const x = Math.max(0, Math.round((box.x - (rect.left - stageRect.left)) * scaleX));
  const y = Math.max(0, Math.round((box.y - (rect.top - stageRect.top)) * scaleY));
  const w = Math.min(canvas.width - x, Math.round(box.w * scaleX));
  const h = Math.min(canvas.height - y, Math.round(box.h * scaleY));
  if (w < 32 || h < 32) return null;
  return { x, y, w, h };
}

function bindQrSelection() {
  const stage = document.getElementById("qr-stage");
  const canvasElement = document.getElementById("qr-canvas");
  if (!stage || !canvasElement || stage.dataset.bound) return;
  stage.dataset.bound = "1";
  let drag = null;

  stage.addEventListener("pointerdown", (event) => {
    if (qrMode !== "screen" || !isQrScanning) return;
    drag = { ...cssPoint(event, stage), pointerId: event.pointerId };
    stage.setPointerCapture(event.pointerId);
    showQrSelection(boxFromPoints(drag, drag));
  });

  stage.addEventListener("pointermove", (event) => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    showQrSelection(boxFromPoints(drag, cssPoint(event, stage)));
  });

  stage.addEventListener("pointerup", (event) => {
    if (!drag || event.pointerId !== drag.pointerId) return;
    const box = boxFromPoints(drag, cssPoint(event, stage));
    drag = null;
    const bitmap = toBitmap(box, canvasElement, stage);
    qrCrop = bitmap;
    showQrSelection(bitmap ? box : null);
  });
}

async function captureScreen() {
  const basic = { video: true, audio: false };
  try {
    return await navigator.mediaDevices.getDisplayMedia({ ...basic, selfBrowserSurface: "exclude" });
  } catch (err) {
    if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) throw err;
    return navigator.mediaDevices.getDisplayMedia(basic);
  }
}

async function startQrCapture(openStream, mode) {
  const video = document.getElementById("qr-video");
  const canvasElement = document.getElementById("qr-canvas");
  const stage = document.getElementById("qr-stage");
  if (!video || !canvasElement) return;
  const canvas = canvasElement.getContext("2d", { willReadFrequently: true });
  stopQrScanner();
  qrMode = mode;
  stage?.classList.toggle("qr-selecting", mode === "screen");
  setQrHint(mode === "screen" ? t("Trascina un riquadro attorno al QR Code.") : "");

  const stream = await openStream();
  qrStream = stream;
  const track = stream.getVideoTracks()[0];
  track?.addEventListener("ended", () => {
    if (qrStream === stream) stopQrScanner();
  });
  video.srcObject = stream;
  video.setAttribute("playsinline", true);
  await video.play();
  isQrScanning = true;
  qrAnimationId = requestAnimationFrame(tick);

  function tick() {
    if (!isQrScanning) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvasElement.height = video.videoHeight;
      canvasElement.width = video.videoWidth;
      canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
      const region = qrMode === "screen" ? qrCrop : { x: 0, y: 0, w: canvasElement.width, h: canvasElement.height };
      if (region && region.w >= 32 && region.h >= 32) {
        const imageData = canvas.getImageData(region.x, region.y, region.w, region.h);
        const code = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "dontInvert" });
        if (code) {
          processQrPresentation(code.data);
          return;
        }
      }
    }
    qrAnimationId = requestAnimationFrame(tick);
  }
}

async function startQrScanner() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    alert(t("La fotocamera non è disponibile. Serve HTTPS oppure localhost."));
    stopQrScanner();
    return;
  }
  try {
    await startQrCapture(
      () => navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }),
      "camera",
    );
  } catch (err) {
    console.error("Impossibile accedere alla fotocamera:", err);
    alert(t("Non riesco a usare la fotocamera. Controlla i permessi."));
    stopQrScanner();
  }
}

async function startScreenPortion() {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
    alert(t("La cattura dello schermo non è disponibile."));
    return;
  }
  try {
    await startQrCapture(captureScreen, "screen");
  } catch (err) {
    if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      startQrScanner();
      return;
    }
    console.error("Impossibile catturare lo schermo:", err);
    alert(t("Non riesco a catturare lo schermo."));
    startQrScanner();
  }
}

function stopQrScanner() {
  isQrScanning = false;
  qrMode = "camera";
  qrCrop = null;
  if (qrAnimationId) {
    cancelAnimationFrame(qrAnimationId);
    qrAnimationId = null;
  }
  const stream = qrStream;
  qrStream = null;
  if (stream) stream.getTracks().forEach((track) => track.stop());
  document.getElementById("qr-stage")?.classList.remove("qr-selecting");
  showQrSelection(null);
  setQrHint("");
}

function handleQrFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const img = new Image();
    img.onload = async function () {
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
        await processQrPresentation(code.data);
      } else {
        alert(t("Non trovo un QR valido in questa immagine. Riprova con un'immagine più nitida."));
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

    closeQrPopup();

    apriPresentationPopup(response_json);
  } catch (err) {
    console.error("Errore durante la presentazione del wallet:", err);
    alert(t("Non riesco a inviare i dati:") + " " + err.message);
  }
}

bindQrSelection();
