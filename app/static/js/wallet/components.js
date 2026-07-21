// --- POPUP REACTION & CLICK-OUTSIDE ---
if (trashIcon && !trashIcon.hasTrashIconHandler) {
  trashIcon.addEventListener("click", (e) => {
    if (trashPopup.classList.contains("popup-visible")) {
      trashPopup.classList.remove("popup-visible");
    } else {
      const rect = trashIcon.getBoundingClientRect();
      trashPopup.style.top = `${rect.bottom + window.scrollY + 5}px`;
      trashPopup.style.left = `${rect.left + window.scrollX}px`;
      trashPopup.classList.add("popup-visible");
    }
  });
  trashIcon.hasTrashIconHandler = true;
}

if (trashPopupCancel && !trashPopupCancel.hasTrashPopupCancelHandler) {
  trashPopupCancel.addEventListener("click", () => trashPopup.classList.remove("popup-visible"));
  trashPopupCancel.hasTrashPopupCancelHandler = true;
}

// Chiudi trashPopup se si clicca fuori dall'area
document.addEventListener("click", (e) => {
  if (!trashPopup.contains(e.target) && !trashIcon.contains(e.target)) {
    trashPopup.classList.remove("popup-visible");
  }
});

// --- SELECT DELLO STATO E BANDIERE ---
function updateFlag(selectedValue) {
  const selected = selectedValue.toLowerCase();
  const flagImg = document.getElementById("flagImage");
  if (selected) {
    flagImg.src = `/static/images/flags/4x3/${selected}.svg`;
  } else {
    flagImg.src = `/static/images/flags/4x3/eu.svg`;
  }
  flagImg.style.display = "block";
}

selectElement.addEventListener('change', function(event) {
  updateFlag(event.target.value);
  initBtn.disabled = false;
});

// Chiamata di avvio UI all'onload
window.onload = function () {
  console.log("Tutto caricato");
  handleInitErrorUI();
};