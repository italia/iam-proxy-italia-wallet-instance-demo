function apriPresentationPopup(response_json) {
    const credentialsPresenting = response_json.data;
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

function chiudiPresentationPopup() {
    const modalElement = document.getElementById('presentation-modal');
    if (modalElement) {
      const modal = bootstrap.Modal.getInstance(modalElement);
      if (modal) modal.hide();
    }
}