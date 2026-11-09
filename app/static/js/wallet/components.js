// --- POPUP REACTION & CLICK-OUTSIDE ---
if (trashIcon && trashPopup && !trashIcon.hasTrashIconHandler) {
  trashIcon.addEventListener("click", () => {
    if (trashPopup.open) {
      trashPopup.close();
    } else {
      trashPopup.showModal();
    }
  });
  trashIcon.hasTrashIconHandler = true;
}

if (trashPopupCancel && trashPopup && !trashPopupCancel.hasTrashPopupCancelHandler) {
  trashPopupCancel.addEventListener("click", () => trashPopup.close());
  trashPopupCancel.hasTrashPopupCancelHandler = true;
}

if (trashPopup) {
  trashPopup.addEventListener("click", (e) => {
    if (e.target === trashPopup) trashPopup.close();
  });
}
