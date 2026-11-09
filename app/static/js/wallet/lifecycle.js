// --- RESET DEL WALLET (TRASH CONFIRM) ---
if (trashPopupConfirm && !trashPopupConfirm.hasTrashPopupConfirmHandler) {
  trashPopupConfirm.addEventListener("click", async () => {
    trashPopup.close();
    spinner.style.display = "flex";
    await new Promise(resolve => setTimeout(resolve, 300));

    try {
      const response = await executeFetch("/itwallet/reset");
      if (!response.ok) throw new Error(await getErrorMessage(response));

      result.innerHTML = `<div class="alert alert-success" role="status"><p>${t("Il wallet è stato reimpostato.")}</p></div>`;

      if (trashIcon) trashIcon.hidden = true;
      if (typeof refreshIssuerCatalog === "function") refreshIssuerCatalog();
    } catch (err) {
      result.innerHTML = `<div class="alert alert-danger" role="alert"><p>${err.message}</p></div>`;
    } finally {
      spinner.style.display = "none";
    }
  });
  trashPopupConfirm.hasTrashPopupConfirmHandler = true;
}
