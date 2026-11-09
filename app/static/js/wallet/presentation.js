let presentationTransactionId = "";
let presentationRelyingParty = {};
let presentationConfirmed = false;

function relyingPartyLine(label, value) {
  if (!value) return null;
  const item = document.createElement("li");
  item.textContent = t(label) + ": " + value;
  return item;
}

function renderRelyingParty(rp) {
  const box = document.getElementById("presentation-rp");
  if (!box) return;
  box.replaceChildren();
  if (!rp || !rp.name) return;
  if (typeof rp.logo_uri === "string" && rp.logo_uri.startsWith("https://")) {
    const logo = document.createElement("img");
    logo.alt = "";
    logo.src = rp.logo_uri;
    box.appendChild(logo);
  }
  const name = document.createElement("p");
  name.className = "mb-1 fw-bold";
  name.textContent = rp.name;
  box.appendChild(name);
  const list = document.createElement("ul");
  list.className = "list-unstyled small text-start mb-0";
  [
    relyingPartyLine("Nome", rp.client_name),
    relyingPartyLine("Identificativo", rp.client_id),
    relyingPartyLine("Sito", rp.homepage_uri),
    relyingPartyLine("Informativa", rp.policy_uri),
    relyingPartyLine("Termini", rp.tos_uri),
    relyingPartyLine("Contatti", Array.isArray(rp.contacts) ? rp.contacts.join(", ") : ""),
  ].forEach((item) => {
    if (item) list.appendChild(item);
  });
  if (list.childElementCount) box.appendChild(list);
}

function apriPresentationPopup(response_json) {
    credentialsPresenting = response_json.data;
    presentationRelyingParty = response_json.relying_party || {};
    presentationTransactionId = response_json.transaction_id || "";
    presentationConfirmed = false;
    renderRelyingParty(presentationRelyingParty);
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

function interruptPresentation() {
  const id = presentationTransactionId;
  presentationTransactionId = "";
  if (!id || presentationConfirmed) return;
  executeFetch("/wallet/presentation/transaction", "POST", { id: id, outcome: "interrotta" }).catch(() => {});
}

function chiudiPresentationPopup() {
  interruptPresentation();
  closePresentationPopup();
}

async function authorizationProcess() {
  presentationConfirmed = true;
  let succeeded = false;
  let reason = "";
  try {
    const response = await executeFetch("/wallet/authorization", "POST", { credentialsPresenting: credentialsPresenting });
    const body = await response.json().catch(() => ({}));
    succeeded = response.ok && body?.success === true;
    if (!succeeded) {
      reason = String(body?.error_message || body?.data?.error || t("Accesso non riuscito.")).replace(/^Exception\s*:/, "").trim();
    }
  } catch (err) {
    reason = reason || err?.message || t("Accesso non riuscito.");
    console.error("Errore durante la presentazione del wallet:", err);
  } finally {
    closePresentationPopup();
    showPresentationResult(succeeded, reason);
  }
}

document.getElementById("presentation-modal")?.addEventListener("hide.bs.modal", () => {
  interruptPresentation();
});

function showPresentationResult(success, reason) {
  const modalElement = document.getElementById('presentation-result-modal');
  const messageElement = document.getElementById('presentation-result-message');
  if (!modalElement || !messageElement) return;

  const successText = t("Consulta la Dashboard Presentazioni per i dettagli dell'avvenuta presentazione.");
  messageElement.textContent = success ? successText : (reason || t("Accesso non riuscito."));
  messageElement.className = success ? "alert alert-success mb-0" : "mt-3 mb-0 text-danger";
  bootstrap.Modal.getOrCreateInstance(modalElement).show();
}
