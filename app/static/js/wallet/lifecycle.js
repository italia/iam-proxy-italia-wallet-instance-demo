// --- FLUSSO INIZIALIZZAZIONE WALLET ---
// (Incluso dentro window.onload nell'originale)
if (initBtn && !initBtn.hasInitHandler) {
  initBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    const selectedIdpRadio = document.querySelector('input[name="idpRadio"]:checked');
    if (!selectedIdpRadio) {
      result.innerHTML = `<div class="alert alert-warning...>Scegli come verificare la tua identità.</div>`;
      return;
    }
    const selectedState = selectElement.value;
    if (!selectedState) {
      result.innerHTML = `<div class="alert alert-warning...">Seleziona uno stato membro...</div>`;
      return;
    }

    result.innerHTML = ``;
    spinner.style.display = "flex";
    const url = `/itwallet/init?idp=${selectedIdpRadio.value}&country=${encodeURIComponent(selectedState)}`;

    try {
      const response = await executeFetch(url);
      if (!response.ok) throw new Error(await getErrorMessage(response));
      const data = await response.json();

      if (data.success) {
        result.innerHTML = "";
        const redirectUrl = data?.data?.redirect_url;
        const popupWidth = 500;
        const popupHeight = 660;
        const left = window.screenX + (window.outerWidth - popupWidth) / 2;
        const top = window.screenY + (window.outerHeight - popupHeight) / 2;

        popupHtml = window.open(redirectUrl, "walletPopup", `width=${popupWidth},height=${popupHeight},left=${left},top=${top},resizable=yes,scrollbars=yes`);
        if (!popupHtml) { alert("Popup bloccato!"); return; }
        popupHtml.focus();

        const popupInterval = setInterval(() => {
          try {
            if (popupHtml.closed) { clearInterval(popupInterval); window.focus(); spinner.style.display = "none"; }
          } catch { /* cross-origin */ }
        }, 500);
      } else {
        result.innerHTML = `<div class="alert alert-danger...">...</div>`;
      }
    } catch (err) {
      result.innerHTML = `<div class="alert alert-danger...">Errore: ${err.message}</div>`;
    } finally {
      if (!popupHtml) spinner.style.display = "none";
    }
  });
  initBtn.hasInitHandler = true;
}

// --- COMPLETAMENTO DA POPUP EXTERNO (OIDC/OAuth PostMessage) ---
window.addEventListener("message", async (event) => {
  if (event.data?.event === "wallet_flow_complete") {
    spinner.style.display = "flex";
    spinner.classList.add("force-visible");
    result.innerHTML = `<div class="flash-container flash-success"><p>Autenticazione completata, recupero PID...</p></div>`;

    try {
      const response = await executeFetch("/itwallet/init/complete", "GET");
      if (!response.ok) throw new Error(await getErrorMessage(response));
      const data = await response.json();

      if (data.success) {
        result.innerHTML = `<div class="flash-container flash-success"><p>Wallet inizializzato con successo!</p></div>`;
        addButton(data?.data?.credential_id); // Nota: deve essere definita altrove

        // Toggle visibilità elementi UI post-inizializzazione
        initBtn.style.display = "none";
        addBtn.style.display = "inline-flex";
        rpBtn.style.display = "inline-flex";
        statesDiv.style.display = "none";
        idpDiv.style.display = "none";
        credentialsBtnDiv.style.display = "flex";
        trashIcon.style.display = "block";
        memoryIcon.style.display = "block";
      } else {
        result.innerHTML = `<div class="flash-container flash-error"><p>${data?.data?.error}</p></div>`;
      }
    } catch (error) {
      result.innerHTML = `<div class="flash-container flash-error"><p>${error.message}</p></div>`;
    } finally {
      spinner.classList.remove("force-visible");
      spinner.style.display = "none";
    }
  }
});

// --- RESET DEL WALLET (TRASH CONFIRM) ---
if (trashPopupConfirm && !trashPopupConfirm.hasTrashPopupConfirmHandler) {
  trashPopupConfirm.addEventListener("click", async () => {
    trashPopup.classList.remove("popup-visible");
    spinner.style.display = "flex";
    await new Promise(resolve => setTimeout(resolve, 300));

    try {
      const response = await executeFetch("/itwallet/reset");
      if (!response.ok) throw new Error(await getErrorMessage(response));

      result.innerHTML = `<div class="alert alert-success...">Il Wallet è stato resettato correttamente</div>`;

      // Reset grafico dell'interfaccia allo stato iniziale
      if (addBtn) addBtn.style.display = "none";
      if (rpBtn) rpBtn.style.display = "none";
      if (credentialsBtnDiv) { credentialsBtnDiv.style.display = "none"; credentialsBtnDiv.innerHTML = ""; }
      if (statesDiv) { statesDiv.style.display = "block"; selectElement.value = ""; }
      if (initBtn) { initBtn.style.display = "inline-flex"; initBtn.disabled = true; }
      if (idpDiv) idpDiv.style.display = "block";
    } catch (err) {
      result.innerHTML = `<div class="alert alert-danger..."><strong>Error:</strong> ${err.message}</div>`;
    } finally {
      spinner.style.display = "none";
    }
  });
  trashPopupConfirm.hasTrashPopupConfirmHandler = true;
}