let presentationTransactionId = "";
let presentationRelyingParty = {};
let presentationConfirmed = false;
let presentationReissueMessage = "";

function presentationRow(label, value) {
  if (!value || (Array.isArray(value) && !value.length)) return null;
  const row = document.createElement("div");
  row.className = "presentation-row";
  const name = document.createElement("div");
  name.className = "presentation-label";
  name.textContent = t(label);
  const content = document.createElement("div");
  content.className = "presentation-value";
  if (Array.isArray(value)) {
    const list = document.createElement("ul");
    list.className = "presentation-values";
    value.forEach(function (item) {
      const entry = document.createElement("li");
      entry.textContent = item;
      list.appendChild(entry);
    });
    content.appendChild(list);
  } else {
    content.textContent = value;
  }
  row.append(name, content);
  return row;
}

function appendPresentationRows(box, rows) {
  rows.forEach(function (row) {
    if (row) box.appendChild(row);
  });
}

function claimPath(claim) {
  if (typeof claim === "string") return claim;
  if (claim && Array.isArray(claim.path)) return claim.path.filter(Boolean).join(".");
  return "";
}

function renderRelyingParty(rp) {
  const box = document.getElementById("presentation-rp");
  if (!box) return;
  box.replaceChildren();
  if (!rp) return;
  if (typeof rp.logo_uri === "string" && rp.logo_uri.startsWith("https://")) {
    const logo = document.createElement("img");
    logo.alt = "";
    logo.src = rp.logo_uri;
    box.appendChild(logo);
  }
  appendPresentationRows(box, [
    presentationRow("Nome", rp.client_name || rp.name),
    presentationRow("Identificativo", rp.client_id),
    presentationRow("Sito", rp.homepage_uri),
    presentationRow("Informativa", rp.policy_uri),
    presentationRow("Termini", rp.tos_uri),
    presentationRow("Contatti", Array.isArray(rp.contacts) ? rp.contacts.join(", ") : ""),
  ]);
}

function renderRequestedAttestations(credentials) {
  const box = document.getElementById("presentation-credentials");
  if (!box) return;
  box.replaceChildren();
  (credentials || []).forEach(function (credential) {
    const block = document.createElement("div");
    block.className = "presentation-credential";
    const paths = (credential.claims || []).map(claimPath).filter(Boolean);
    appendPresentationRows(block, [
      presentationRow("Identificativo", credential.id || ""),
      presentationRow("Formato", credential.format || ""),
      presentationRow("Attributi", paths),
    ]);
    box.appendChild(block);
  });
}

function showPresentationWarning(warning) {
  const box = document.getElementById("presentation-warning");
  const confirmButton = document.getElementById("presentation-confirm");
  const continueButton = document.getElementById("presentation-continue");
  const reissueButton = document.getElementById("presentation-reissue");
  const blocked = Boolean(warning && warning.message);
  presentationReissueMessage = blocked ? String(warning.reissue || "") : "";
  if (box) {
    box.textContent = blocked ? warning.message : "";
    box.classList.toggle("d-none", !blocked);
  }
  confirmButton?.classList.toggle("d-none", blocked);
  continueButton?.classList.toggle("d-none", !blocked);
  reissueButton?.classList.toggle("d-none", !blocked);
}

function apriPresentationPopup(response_json) {
  credentialsPresenting = response_json.data;
  presentationRelyingParty = response_json.relying_party || {};
  presentationTransactionId = response_json.transaction_id || "";
  presentationConfirmed = false;
  renderRelyingParty(presentationRelyingParty);
  renderRequestedAttestations(credentialsPresenting);
  showPresentationWarning(response_json.credential_warning || {});
  const presentationModalComponent = document.getElementById("presentation-modal");
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

function requestNewIssuance() {
  const text = presentationReissueMessage;
  chiudiPresentationPopup();
  showPresentationResult(false, text, "warning");
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

function showPresentationResult(success, reason, tone) {
  const modalElement = document.getElementById('presentation-result-modal');
  const messageElement = document.getElementById('presentation-result-message');
  if (!modalElement || !messageElement) return;

  const successText = t("Consulta la Dashboard Presentazioni per i dettagli dell'avvenuta presentazione.");
  messageElement.textContent = success ? successText : (reason || t("Accesso non riuscito."));
  if (success) messageElement.className = "alert alert-success mb-0";
  else if (tone === "warning") messageElement.className = "alert alert-warning mb-0";
  else messageElement.className = "mt-3 mb-0 text-danger";
  bootstrap.Modal.getOrCreateInstance(modalElement).show();
}
