

function apriPresentationPopup(response_json) {
    credentialsPresenting = response_json.data;
    const descrizioni = credentialsPresenting.map(cred => {
      const name = `<b>${cred.id}</b> in ${cred.format}`;
      const claimsPaths = (cred.claims || [])
        .map(c => c.path?.join("."))
        .filter(Boolean);
      const claimsList = claimsPaths.length > 0
        ? `<ul>` + claimsPaths.map(path => `<li>${path}</li>`).join("") + `</ul>`
        : "";

      return `<li>${name}${claimsList}</li>`;
    });
    const frase = `
      <ul style="margin-top: 0px; padding-left: 20px;">${descrizioni.join("")}</ul>
    `;
    const claimsListContainer = document.getElementById('presentation-claims-list');
    if (claimsListContainer) {
        claimsListContainer.innerHTML = frase;
    }
    const presentationModalComponent = document.getElementById('presentation-modal');
    if (!presentationModalComponent) return;
    const presentationModal = new bootstrap.Modal(presentationModalComponent);
    presentationModal.show();
}

function closePresentationPopup() {
    const modalElement = document.getElementById('presentation-modal');
    if (modalElement) {
      const modal = bootstrap.Modal.getInstance(modalElement);
      if (modal) modal.hide();
    }
}

async function authorizationProcess() {
  var result = false;
  try {
    const response = await executeFetch("/wallet/authorization", "POST", { credentialsPresenting: credentialsPresenting });
    if (!response.ok) {
      throw new Error(await getErrorMessage(response));
    }

    response_json = await response.json();
    result = response_json?.success === true;

  } catch (err) {
    console.error("Errore durante la presentazione del wallet:", err);
  }
  finally{
    closePresentationPopup();
    showPresentationResult(result);
  }
}

function showPresentationResult(success) {
  const modalElement = document.getElementById('presentation-result-modal');
  const messageElement = document.getElementById('presentation-result-message');
  if (!modalElement || !messageElement) return;

  messageElement.textContent = success ? "Login completato con successo." : "Login fallito.";
  messageElement.className = `mt-3 mb-0 ${success ? "text-success" : "text-danger"}`;
  bootstrap.Modal.getOrCreateInstance(modalElement).show();
}