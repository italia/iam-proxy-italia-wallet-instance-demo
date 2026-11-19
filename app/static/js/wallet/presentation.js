let presentationTransactionId = "";
let presentationRelyingParty = {};
let presentationConfirmed = false;
let presentationAuthorizationRequest = {};

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
  } else if (value instanceof Node) {
    content.appendChild(value);
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

function claimId(claim, index) {
  if (claim && typeof claim.id === "string" && claim.id) return claim.id;
  return claimPath(claim) || String(index);
}

function requiredClaimIds(credential) {
  const claims = credential.claims || [];
  const claimSets = credential.claim_sets;
  if (!Array.isArray(claimSets) || !claimSets.length) {
    return claims.map(function (claim, index) {
      return claimId(claim, index);
    });
  }
  let required = null;
  claimSets.forEach(function (set) {
    if (!Array.isArray(set)) return;
    const ids = new Set(set.filter(Boolean));
    if (required === null) {
      required = ids;
      return;
    }
    required = new Set(
      Array.from(required).filter(function (id) {
        return ids.has(id);
      })
    );
  });
  return required ? Array.from(required) : [];
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

function claimSelectionList(credential, credIndex) {
  const claims = credential.claims || [];
  if (!claims.length) return null;
  const required = new Set(requiredClaimIds(credential));
  const list = document.createElement("ul");
  list.className = "presentation-claim-list";
  claims.forEach(function (claim, claimIndex) {
    const id = claimId(claim, claimIndex);
    const path = claimPath(claim) || id;
    const mandatory = required.has(id);
    const item = document.createElement("li");
    item.className = "presentation-claim-item";
    const inputId = `presentation-claim-${credIndex}-${claimIndex}`;
    const input = document.createElement("input");
    input.type = "checkbox";
    input.className = "form-check-input";
    input.id = inputId;
    input.checked = mandatory;
    input.disabled = mandatory;
    input.dataset.claimId = id;
    const label = document.createElement("label");
    label.className = "form-check-label";
    label.htmlFor = inputId;
    const name = document.createElement("span");
    name.className = "presentation-claim-name";
    name.textContent = path;
    const badge = document.createElement("span");
    badge.className = mandatory ? "presentation-claim-badge presentation-claim-badge-required" : "presentation-claim-badge presentation-claim-badge-optional";
    badge.textContent = mandatory ? t("Obbligatorio") : t("Opzionale");
    label.append(name, badge);
    item.append(input, label);
    list.appendChild(item);
  });
  return list;
}

function renderRequestedAttestations(credentials) {
  const box = document.getElementById("presentation-credentials");
  if (!box) return;
  box.replaceChildren();
  (credentials || []).forEach(function (credential, credIndex) {
    const block = document.createElement("div");
    block.className = "presentation-credential";
    appendPresentationRows(block, [
      presentationRow("Identificativo", credential.id || ""),
      presentationRow("Formato", credential.format || ""),
      presentationRow("Attributi", claimSelectionList(credential, credIndex)),
    ]);
    box.appendChild(block);
  });
}

function prettyPresentationJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (err) {
    return String(value || "");
  }
}

function setPresentationRequestToggle(expanded) {
  const toggle = document.getElementById("presentation-request-toggle");
  if (!toggle) return;
  toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
  toggle.textContent = expanded ? t("Nascondi richiesta del verificatore") : t("Mostra richiesta del verificatore");
}

function renderAuthorizationRequest(payload) {
  const pre = document.getElementById("presentation-request-json");
  const collapse = document.getElementById("presentation-request-collapse");
  if (pre) {
    pre.textContent = payload && Object.keys(payload).length ? prettyPresentationJson(payload) : "";
  }
  if (collapse) {
    collapse.classList.remove("show");
  }
  setPresentationRequestToggle(false);
}

function showPresentationWarning(warning) {
  const box = document.getElementById("presentation-warning");
  const confirmButton = document.getElementById("presentation-confirm");
  const continueButton = document.getElementById("presentation-continue");
  const reissueButton = document.getElementById("presentation-reissue");
  const blocked = Boolean(warning && warning.message);
  if (box) {
    box.textContent = blocked ? warning.message : "";
    box.classList.toggle("d-none", !blocked);
  }
  confirmButton?.classList.toggle("d-none", blocked);
  continueButton?.classList.toggle("d-none", !blocked);
  reissueButton?.classList.toggle("d-none", !blocked);
}

function selectedCredentialsPresenting() {
  return (credentialsPresenting || []).map(function (credential, credIndex) {
    const claims = credential.claims || [];
    const selected = claims.filter(function (claim, claimIndex) {
      const input = document.getElementById(`presentation-claim-${credIndex}-${claimIndex}`);
      return !input || input.checked;
    });
    return Object.assign({}, credential, { claims: selected });
  });
}

function apriPresentationPopup(response_json) {
  credentialsPresenting = response_json.data;
  presentationRelyingParty = response_json.relying_party || {};
  presentationTransactionId = response_json.transaction_id || "";
  presentationAuthorizationRequest = response_json.authorization_request || {};
  presentationConfirmed = false;
  renderRelyingParty(presentationRelyingParty);
  renderRequestedAttestations(credentialsPresenting);
  renderAuthorizationRequest(presentationAuthorizationRequest);
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
  chiudiPresentationPopup();
  window.location.assign("/wallet/home");
}

async function authorizationProcess() {
  presentationConfirmed = true;
  let succeeded = false;
  let reason = "";
  try {
    const response = await executeFetch("/wallet/authorization", "POST", {
      credentialsPresenting: selectedCredentialsPresenting(),
    });
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

document.getElementById("presentation-request-collapse")?.addEventListener("shown.bs.collapse", () => {
  setPresentationRequestToggle(true);
});

document.getElementById("presentation-request-collapse")?.addEventListener("hidden.bs.collapse", () => {
  setPresentationRequestToggle(false);
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
