// Inizializzazione Carosello esterno
document.addEventListener('DOMContentLoaded', function () {
  new Splide('.it-carousel-wrapper', {
    type: 'loop',
    perPage: 3,
    gap: '1rem',
    height: 'auto',
    arrows: true,
  }).mount();
});

// Funzione di blocco UI in caso di errore di inizializzazione a monte
function handleInitErrorUI() {
  if (!INIT_ERROR_MESSAGE) return;
  console.log("Init error rilevato:", INIT_ERROR_MESSAGE);

  if (idpDiv) {
    const radios = idpDiv.querySelectorAll("input[type='radio']");
    radios.forEach(radio => radio.disabled = true);
    idpDiv.style.opacity = "0.5";
    idpDiv.style.pointerEvents = "none";
    document.getElementById("state_container").style.display = "none";
  }
  if (selectElement) {
    selectElement.disabled = true;
  }
  const buttonsContainer = document.getElementById("buttons_containers");
  if (buttonsContainer) {
    const buttons = buttonsContainer.querySelectorAll("button, a");
    buttons.forEach(btn => {
      btn.disabled = true;
      btn.classList.add("disabled");
    });
    buttonsContainer.style.opacity = "0.5";
    buttonsContainer.style.pointerEvents = "none";
    buttonsContainer.style.display = "none";
  }
}

// Comportamento dello spinner in caso di click
if (!spinner.hasPopupFocusHandler) {
  spinner.addEventListener("click", () => {
    if (popupHtml && !popupHtml.closed) popupHtml.focus();
  });
  spinner.hasPopupFocusHandler = true;
}

// Chiusura popups con il tasto ESC
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeCredPopup(); // Nota: assicurati che questa funzione sia definita globalmente
  }
});