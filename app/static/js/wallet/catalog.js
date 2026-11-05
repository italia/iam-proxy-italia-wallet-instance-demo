function escapeCatalogText(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function catalogSectionHtml(section, sectionIndex) {
  const options = [
    `<option value="" selected>${t("Scegli un'attestazione")}</option>`,
    ...(section.attestations || []).map((item) => {
      const obtained = item.obtained ? ` — ${t("Già ottenuta")}` : "";
      const disabled = item.obtained ? " disabled" : "";
      return `<option value="${escapeCatalogText(item.id)}" data-description="${escapeCatalogText(item.description || "")}" data-claims="${escapeCatalogText(JSON.stringify(item.claims || []))}" data-format="${escapeCatalogText(item.format || "")}"${disabled}>${escapeCatalogText(item.name)}${obtained}</option>`;
    }),
  ].join("");
  const selectId = `issuer-select-${sectionIndex}`;
  return `
    <article class="it-card rounded border shadow-sm catalog-section mb-4" data-issuer="${escapeCatalogText(section.issuer)}">
      <div class="it-card-body p-4">
        <h2 class="h5">${escapeCatalogText(section.issuer)}</h2>
        <div class="form-group mb-0">
          <div class="input-group align-items-end">
            <div class="select-wrapper flex-grow-1">
              <label for="${selectId}">${t("Attestazione")}</label>
              <select id="${selectId}" data-source="${escapeCatalogText(section.source || "")}" aria-describedby="${selectId}-detail ${selectId}-error">
                ${options}
              </select>
            </div>
            <div class="input-group-append">
              <button type="button" class="btn btn-primary obtain-one">${t("Ottieni")}</button>
            </div>
          </div>
          <p id="${selectId}-error" class="field-error" hidden></p>
          <div id="${selectId}-detail" class="attestation-detail mt-3"></div>
        </div>
      </div>
    </article>`;
}

function renderCatalogSections(sections) {
  const catalog = document.getElementById("issuer-catalog");
  if (!catalog) return;
  catalog.innerHTML = (sections || []).map((section, index) => catalogSectionHtml(section, index)).join("");
}

function upsertCatalogSection(section) {
  const catalog = document.getElementById("issuer-catalog");
  if (!catalog || !section) return;
  const existing = catalog.querySelector(`article[data-issuer="${CSS.escape(section.issuer)}"]`);
  const html = catalogSectionHtml(section, catalog.querySelectorAll(".catalog-section").length);
  if (existing) {
    existing.outerHTML = html;
  } else {
    catalog.insertAdjacentHTML("beforeend", html);
  }
}

function setIssuerUrlError(message) {
  const input = document.getElementById("issuer-url");
  const error = document.getElementById("issuer-url-error");
  if (error) {
    error.hidden = !message;
    error.textContent = message || "";
  }
  if (input) {
    if (message) input.setAttribute("aria-invalid", "true");
    else input.removeAttribute("aria-invalid");
  }
}

function claimLabels(raw) {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.map((item) => String(item || "").trim()).filter(Boolean);
  } catch (error) {
    return String(raw).split(",").map((item) => item.trim()).filter(Boolean);
  }
  return [];
}

function readableFormat(value) {
  const names = {
    "dc+sd-jwt": "SD-JWT",
    "vc+sd-jwt": "SD-JWT",
    mso_mdoc: "mdoc",
    jwt_vc_json: "JWT",
  };
  return names[value] || value;
}

function previewRow(label, content) {
  const row = document.createElement("div");
  row.className = "attestation-preview-row";
  const term = document.createElement("dt");
  term.textContent = label;
  const value = document.createElement("dd");
  if (typeof content === "string") value.textContent = content;
  else value.append(content);
  row.append(term, value);
  return row;
}

function fillAttestationDetail(select) {
  const detail = select?.closest(".form-group")?.querySelector(".attestation-detail");
  if (!detail) return;
  detail.replaceChildren();
  const option = select.selectedOptions?.[0];
  if (!option || !option.value) return;

  const list = document.createElement("dl");
  list.className = "attestation-preview";
  const configId = document.createElement("code");
  configId.className = "attestation-config-id";
  configId.textContent = option.value;
  list.append(previewRow(t("Identificativo di configurazione"), configId));
  const source = select.dataset.source || "";
  if (source) {
    const sourceLink = document.createElement("a");
    sourceLink.className = "attestation-source";
    sourceLink.href = source;
    sourceLink.textContent = source;
    list.append(previewRow(t("Fonte"), sourceLink));
  }
  const description = option.dataset.description || "";
  const format = option.dataset.format || "";
  const claims = claimLabels(option.dataset.claims || "");
  if (description) list.append(previewRow(t("Descrizione"), description));
  if (format) list.append(previewRow(t("Formato"), readableFormat(format)));
  if (claims.length) {
    const claimsList = document.createElement("ul");
    claimsList.className = "attestation-claims";
    claims.forEach((claim) => {
      const item = document.createElement("li");
      item.textContent = claim;
      claimsList.append(item);
    });
    list.append(previewRow(t("Dati contenuti"), claimsList));
  }
  if (list.childElementCount) detail.append(list);
}

function openCredPopup() {
  if (typeof credPopup === "undefined" || !credPopup) return;
  credPopup.classList.add("show");
  credPopup.setAttribute("aria-hidden", "false");
  if (typeof credPopupTitle !== "undefined" && credPopupTitle) {
    credPopupTitle.textContent = t("Ottieni attestazione");
  }
}

async function refreshIssuerCatalog() {
  const response = await executeFetch("/itwallet/issuerCatalog", "GET");
  if (!response.ok) return;
  const data = await response.json();
  if (data.success) renderCatalogSections(data.data);
}

function decodeJwtPart(part) {
  const padded = part.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (part.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  const text = new TextDecoder().decode(bytes);
  try {
    return JSON.parse(text);
  } catch (error) {
    return text;
  }
}

function jwtTokensIn(text) {
  const pattern = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
  const tokens = [];
  for (const match of String(text).matchAll(pattern)) {
    const token = match[0];
    try {
      const header = decodeJwtPart(token.split(".")[0]);
      if (header && typeof header === "object" && (header.alg || header.typ || header.kid)) tokens.push(token);
    } catch (error) {
      /* not a readable JWT */
    }
  }
  return tokens;
}

function collectJwts(value, path, found) {
  if (typeof value === "string") {
    jwtTokensIn(value).forEach((token) => found.push({ path, token }));
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => collectJwts(item, `${path}[${index}]`, found));
    return;
  }
  if (value && typeof value === "object") {
    Object.entries(value).forEach(([key, item]) => collectJwts(item, path ? `${path}.${key}` : key, found));
  }
}

function jwtCleartext(token) {
  const [headerPart, payloadPart] = token.split(".");
  const header = decodeJwtPart(headerPart);
  let payload = decodeJwtPart(payloadPart);
  if (header && typeof header === "object" && header.enc) {
    payload = t("Payload cifrato: serve la chiave del destinatario per leggerlo.");
  }
  return { header, payload };
}

function pretty(value) {
  return typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

let diagnosticJwtSeq = 0;

function jwtTabs(found) {
  const wrapper = document.createDocumentFragment();
  found.forEach((item) => {
    const { header, payload } = jwtCleartext(item.token);
    const seq = diagnosticJwtSeq++;
    const headerId = `diagnostic-jwt-${seq}-header`;
    const payloadId = `diagnostic-jwt-${seq}-payload`;
    const block = document.createElement("div");
    block.className = "diagnostic-jwt mt-2";
    const where = document.createElement("p");
    where.className = "diagnostic-jwt-path mb-1";
    where.textContent = item.path || "JWT";
    const tabs = document.createElement("ul");
    tabs.className = "nav nav-tabs";
    tabs.setAttribute("role", "tablist");
    tabs.innerHTML = `
      <li class="nav-item" role="presentation">
        <button class="nav-link active" id="${headerId}-tab" type="button" role="tab" data-bs-toggle="tab" data-bs-target="#${headerId}" aria-controls="${headerId}" aria-selected="true">${t("Header")}</button>
      </li>
      <li class="nav-item" role="presentation">
        <button class="nav-link" id="${payloadId}-tab" type="button" role="tab" data-bs-toggle="tab" data-bs-target="#${payloadId}" aria-controls="${payloadId}" aria-selected="false">${t("Payload")}</button>
      </li>`;
    const panes = document.createElement("div");
    panes.className = "tab-content diagnostic-jwt-panes";
    const headerPane = document.createElement("div");
    headerPane.className = "tab-pane fade show active";
    headerPane.id = headerId;
    headerPane.setAttribute("role", "tabpanel");
    headerPane.setAttribute("aria-labelledby", `${headerId}-tab`);
    const headerPre = document.createElement("pre");
    headerPre.className = "mb-0";
    headerPre.textContent = pretty(header);
    headerPane.append(headerPre);
    const payloadPane = document.createElement("div");
    payloadPane.className = "tab-pane fade";
    payloadPane.id = payloadId;
    payloadPane.setAttribute("role", "tabpanel");
    payloadPane.setAttribute("aria-labelledby", `${payloadId}-tab`);
    const payloadPre = document.createElement("pre");
    payloadPre.className = "mb-0";
    payloadPre.textContent = pretty(payload);
    payloadPane.append(payloadPre);
    panes.append(headerPane, payloadPane);
    block.append(where, tabs, panes);
    wrapper.append(block);
  });
  return wrapper;
}

function diagnosticBlock(label, value) {
  const fragment = document.createDocumentFragment();
  const title = document.createElement("p");
  title.className = "mb-1";
  title.textContent = label;
  const raw = document.createElement("pre");
  raw.className = "border rounded p-2 bg-light";
  raw.textContent = JSON.stringify(value, null, 2);
  fragment.append(title, raw);
  const found = [];
  collectJwts(value, "", found);
  if (found.length) fragment.append(jwtTabs(found));
  return fragment;
}

function renderDiagnostics(entries) {
  const box = document.getElementById("diagnostic-log");
  if (!box) return;
  if (!entries?.length) {
    box.innerHTML = `<p class="mb-0">${t("Nessuno scambio registrato.")}</p>`;
    return;
  }
  box.replaceChildren();
  for (const entry of [...entries].reverse()) {
    const article = document.createElement("article");
    article.className = "border-bottom py-3";
    const heading = document.createElement("p");
    heading.className = "mb-1";
    const peer = document.createElement("strong");
    const peerNames = {
      credential_issuer: t("Issuer di credenziali"),
      relying_party: t("Verificatore"),
      federation: t("Federazione"),
    };
    peer.textContent = peerNames[entry.peer] || entry.peer || "";
    heading.append(peer, ` ${entry.method || ""} ${entry.status ?? ""}`);
    const url = document.createElement("p");
    url.className = "mb-2";
    url.textContent = entry.url || "";
    article.append(heading, url, diagnosticBlock(t("Richiesta"), entry.request), diagnosticBlock(t("Risposta"), entry.response));
    box.appendChild(article);
  }
}

async function refreshDiagnostics() {
  const headers = {};
  if (typeof SESSION_ID !== "undefined" && SESSION_ID) {
    headers["X-Correlation-ID"] = SESSION_ID;
  }
  const response = await fetch("/itwallet/diagnostics", { headers });
  if (!response.ok) return;
  const data = await response.json();
  if (data.success) renderDiagnostics(data.data || []);
}

document.getElementById("issuer-catalog")?.addEventListener("change", (event) => {
  const select = event.target.closest("select");
  if (!select) return;
  fillAttestationDetail(select);
  const error = select.closest(".form-group")?.querySelector(".field-error");
  if (select.value) {
    select.removeAttribute("aria-invalid");
    if (error) {
      error.hidden = true;
      error.textContent = "";
    }
  }
});

document.getElementById("issuer-catalog")?.addEventListener("click", (event) => {
  const button = event.target.closest(".obtain-one");
  if (!button) return;
  const card = button.closest(".catalog-section");
  const select = card?.querySelector("select");
  const error = card?.querySelector(".field-error");
  if (!select || !select.value) {
    if (select) select.setAttribute("aria-invalid", "true");
    if (error) {
      error.hidden = false;
      error.textContent = t("Seleziona un'attestazione.");
    }
    return;
  }
  select.removeAttribute("aria-invalid");
  if (error) {
    error.hidden = true;
    error.textContent = "";
  }
  selectedValue = select.value;
  if (typeof obtainQueue !== "undefined") obtainQueue = [];
  if (typeof openCredPopup === "function") openCredPopup();
  confirmAddCredential();
});

document.getElementById("issuer-catalog-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.getElementById("issuer-url");
  const issuerUrl = input?.value?.trim() || "";
  if (!issuerUrl) {
    setIssuerUrlError(t("Inserisci un URL http o https."));
    return;
  }
  setIssuerUrlError("");
  const response = await executeFetch("/itwallet/issuerCatalog", "POST", { issuerUrl });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.success) {
    setIssuerUrlError(data.message || t("Impossibile leggere i metadata di questo issuer."));
    return;
  }
  if (input) input.value = "";
  upsertCatalogSection(data.data);
});

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("diagnostic-log")) refreshDiagnostics();
  const issued = new URLSearchParams(window.location.search).get("issued");
  if (issued === "1" && typeof continueAddCredential === "function") {
    const url = new URL(window.location.href);
    url.searchParams.delete("issued");
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
    if (typeof openCredPopup === "function") openCredPopup();
    continueAddCredential();
  }
});
