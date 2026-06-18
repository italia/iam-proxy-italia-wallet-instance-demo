// --- COMPONENTE AGGIUNGI CREDENZIALE ---
if (addBtn && !addBtn.hasAddHandler) {
  addBtn.addEventListener("click", async (e) => {
    e.preventDefault();
    result.innerHTML = ``;
    credPopup.classList.add("show");
    credPopupBody.style.minHeight = "300px";
    credPopupTitle.innerHTML = "Aggiungi Credenziale";
    credPopupBody.innerHTML = `<div class="spinner-wrapper"><div class="spinner"></div><p>Caricamento...</p></div>`;

    await new Promise(resolve => setTimeout(resolve, 300));

    try {
      const response = await executeFetch("/itwallet/credentialSupported");
      if (!response.ok) throw new Error(await getErrorMessage(response));
      const data = await response.json();

      if (data.success) {
        credPopupBody.innerHTML = `...[Render Dropdown con data.data]...`; // Costruzione del menu custom dell'originale
        // Aggancio logica di selezione ed esecuzione di confirmAddCredential(selectedValue)
      } else {
        credPopupBody.innerHTML = `<div class="flash-error"><p>${data?.data?.error}</p></div>`;
      }
    } catch (err) {
      credPopupBody.innerHTML = `<div class="flash-error"><p>Fallito recupero credenziali: ${err.message}</p></div>`;
    }
  });
  addBtn.hasAddHandler = true;
}

// --- ISPEZIONE DELLA MEMORIA DEL WALLET ---
if (memoryIcon && !memoryIcon.hasMemoryIconHandler) {
  memoryIcon.addEventListener("click", async (e) => {
    e.preventDefault();
    result.innerHTML = ``;
    credPopup.classList.add("show");
    credPopupTitle.innerHTML = "Ispeziona memoria";
    credPopupBody.innerHTML = `<div class="spinner-wrapper"><div class="spinner"></div><p>Caricamento...</p></div>`;

    try {
      const response = await executeFetch("/itwallet/objectTypesInMemory");
      if (!response.ok) throw new Error(await getErrorMessage(response));
      const data = await response.json();

      if (data.success) {
        const mappedTypes = data.data.map(type => ({ id: type, label: type, icon: "📦" }));
        credPopupBody.innerHTML = `...[Render Dropdown per Oggetti in memoria]...`;
        // Aggancio logica per confirmViewObjectTypeInMemory(selectedValue)
      } else {
        credPopupBody.innerHTML = `<div class="flash-error"><p>${data?.data?.error}</p></div>`;
      }
    } catch (err) {
      credPopupBody.innerHTML = `<div class="flash-error"><p>Errore memoria: ${err.message}</p></div>`;
    }
  });
  memoryIcon.hasMemoryIconHandler = true;
}

// --- DETTAGLIO MODALE BOOTSTRAP (Visualizzazione dati credenziale) ---
if (template) {
  template.addEventListener('shown.bs.modal', async function (event) {
    const button = event.relatedTarget;
    const button_split = button.id.split(":");
    const input_body = {
      issuer: button_split.slice(0, -1).join(":"),
      key: button_split.pop()
    };
    try {
      const response = await executeFetch("/wallet/detail", "POST", input_body);
      if (!response.ok) throw new Error(await getErrorMessage(response));
      document.getElementById("modal-body-detail").innerHTML = await response.text();
    } catch (err) {
      console.error(err);
    }
  });
}