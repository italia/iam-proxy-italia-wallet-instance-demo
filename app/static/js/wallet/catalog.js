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
      const format = readableFormat(item.format || "");
      const formatLabel = format ? ` — ${format}` : "";
      const sameLabel = (section.attestations || []).filter(
        (other) => other.name === item.name && (other.format || "") === (item.format || "")
      );
      const disambiguator = sameLabel.length > 1 ? ` — ${item.id}` : "";
      const disabled = item.obtained ? " disabled" : "";
      return `<option value="${escapeCatalogText(item.id)}" data-description="${escapeCatalogText(item.description || "")}" data-claims="${escapeCatalogText(JSON.stringify(item.claims || []))}" data-format="${escapeCatalogText(item.format || "")}" data-offer-uri="${escapeCatalogText(item.offer_uri || "")}"${disabled}>${escapeCatalogText(item.name)}${escapeCatalogText(formatLabel)}${escapeCatalogText(disambiguator)}${obtained}</option>`;
    }),
  ].join("");
  const selectId = `issuer-select-${sectionIndex}`;
  return `
    <article class="it-card rounded border shadow-sm catalog-section mb-4" data-issuer="${escapeCatalogText(section.issuer)}">
      <div class="it-card-body p-4">
        <h2 class="catalog-issuer">
          <span><span class="catalog-issuer-label">${t("Nome del credential issuer")}:</span> ${escapeCatalogText(section.name || "")}</span>
          <span><span class="catalog-issuer-label">${t("URI del credential issuer")}:</span> ${escapeCatalogText(section.uri || section.issuer || "")}</span>
          <span><span class="catalog-issuer-label">${t("Numero di credenziali offerte")}:</span> ${escapeCatalogText((section.attestations || []).length)}</span>
        </h2>
        <div class="form-group mb-0">
          <div class="catalog-obtain">
            <div class="select-wrapper">
              <label for="${selectId}">${t("Attestazione")}</label>
              <select id="${selectId}" data-source="${escapeCatalogText(section.source || "")}" aria-describedby="${selectId}-detail ${selectId}-error">
                ${options}
              </select>
            </div>
            <button type="button" class="btn btn-primary obtain-one">${t("Ottieni")}</button>
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

function setDiscoveryError(message) {
  const select = document.getElementById("issuer-discovery");
  const error = document.getElementById("issuer-discovery-error");
  if (error) {
    error.hidden = !message;
    error.textContent = message || "";
  }
  if (select) {
    if (message) select.setAttribute("aria-invalid", "true");
    else select.removeAttribute("aria-invalid");
  }
}

function discoveryValue() {
  return document.getElementById("issuer-discovery")?.value || "openid-federation";
}

function syncTrustAnchor() {
  const input = document.getElementById("trust-anchor");
  if (!input) return;
  const mode = discoveryValue();
  if (mode === "eudiw-lotl") {
    input.value = input.dataset.eudiwLotl || "";
    return;
  }
  input.value = input.dataset.composeTrustAnchor || "";
}

function syncDiscoveryMode() {
  const select = document.getElementById("issuer-discovery");
  const pending = discoveryValue() === "eudiw-lotl";
  select?.classList.toggle("discovery-pending", pending);
  setDiscoveryError(pending ? t("eudiw lotl non è ancora implementato.") : "");
  syncTrustAnchor();
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
    mso_mdoc: "mdoc CBOR",
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

function appendCredentialOffer(list, option) {
  const offer = option.dataset.offerUri || "";
  if (!offer) return;
  const link = document.createElement("a");
  link.className = "attestation-source long-text";
  link.href = offer;
  link.textContent = offer;
  list.append(previewRow(t("Credential offer"), link));
  const image = document.createElement("img");
  image.className = "credential-offer-qr";
  image.alt = t("QR code della credential offer");
  image.src = `/itwallet/credential-offer.svg?offer=${encodeURIComponent(offer)}`;
  list.append(previewRow(t("QR code della credential offer"), image));
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
  configId.className = "attestation-config-id long-text";
  configId.textContent = option.value;
  list.append(previewRow(t("Identificativo di configurazione"), configId));
  const source = select.dataset.source || "";
  if (source) {
    const sourceLink = document.createElement("a");
    sourceLink.className = "attestation-source long-text";
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
  appendCredentialOffer(list, option);
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

const DIAGNOSTIC_PURPOSES = [
  ["openid-federation", "Configurazione di entità"],
  ["openid-credential-issuer", "Metadata dell'issuer"],
  ["par", "Pushed authorization"],
  ["pushed_authorization_request", "Pushed authorization"],
  ["token", "Token"],
  ["nonce", "Nonce"],
  ["credential", "Rilascio dell'attestazione"],
  ["request_uri", "Request URI"],
  ["request-uri", "Request URI"],
  ["direct_post", "Risposta di presentazione"],
  ["authorize", "Autorizzazione"],
  ["list", "Elenco di federazione"],
];

function diagnosticPurpose(url) {
  let segments = [];
  try {
    segments = new URL(url).pathname.toLowerCase().split("/").filter(Boolean);
  } catch (error) {
    segments = String(url || "").toLowerCase().split("?")[0].split("/").filter(Boolean);
  }
  if (segments.includes("status")) return "Status List";
  const last = segments.at(-1) || "";
  const match = DIAGNOSTIC_PURPOSES.find(([segment]) => segment === last);
  return match ? match[1] : "Altro";
}

function diagnosticFailed(entry) {
  if (entry.status === null || entry.status === undefined || entry.status === "") return true;
  const status = Number(entry.status);
  return !Number.isFinite(status) || status >= 400;
}

function diagnosticStamp(entry) {
  const time = entry.time ? new Date(entry.time) : null;
  const clock = time && !Number.isNaN(time.getTime())
    ? time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : "";
  return [entry.method || "", entry.status ?? "", clock].filter((part) => part !== "").join(" ");
}

function renderDiagnosticNav(items) {
  const list = document.getElementById("diagnostic-nav-list");
  if (!list) return;
  list.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "mb-0";
    empty.textContent = t("Nessuno scambio registrato.");
    list.append(empty);
    return;
  }
  const groups = new Map();
  items.forEach((item) => {
    if (!groups.has(item.purpose)) groups.set(item.purpose, []);
    groups.get(item.purpose).push(item);
  });
  groups.forEach((calls, purpose) => {
    const group = document.createElement("section");
    group.className = "diagnostic-nav-group";
    const title = document.createElement("h3");
    title.textContent = t(purpose);
    const menu = document.createElement("ul");
    calls.forEach((call) => {
      const row = document.createElement("li");
      const link = document.createElement("a");
      link.href = `#${call.id}`;
      link.textContent = call.label;
      if (call.failed) link.classList.add("is-failed");
      link.addEventListener("click", (event) => {
        const target = document.getElementById(call.id);
        if (!target) return;
        event.preventDefault();
        list.querySelectorAll("a[aria-current]").forEach((current) => current.removeAttribute("aria-current"));
        link.setAttribute("aria-current", "true");
        target.scrollIntoView({ behavior: "smooth", block: "start" });
        history.replaceState(null, "", `#${call.id}`);
      });
      row.append(link);
      menu.append(row);
    });
    group.append(title, menu);
    list.append(group);
  });
}

let diagnosticEntries = [];

function diagnosticPeerName(peer) {
  const peerNames = {
    credential_issuer: t("Issuer di credenziali"),
    relying_party: t("Verificatore"),
    federation: t("Federazione"),
  };
  return peerNames[peer] || peer || "";
}

function syncDiagnosticToolbar() {
  const boxes = [...document.querySelectorAll(".diagnostic-select-input")];
  const checked = boxes.filter((box) => box.checked).length;
  const remove = document.getElementById("diagnostic-remove");
  const selectAll = document.getElementById("diagnostic-select-all");
  const exportText = document.getElementById("diagnostic-export-text");
  const exportJson = document.getElementById("diagnostic-export-json");
  if (remove) remove.disabled = checked === 0;
  if (selectAll) {
    selectAll.disabled = boxes.length === 0;
    selectAll.checked = boxes.length > 0 && checked === boxes.length;
    selectAll.indeterminate = checked > 0 && checked < boxes.length;
  }
  const empty = diagnosticEntries.length === 0;
  if (exportText) exportText.disabled = empty;
  if (exportJson) exportJson.disabled = empty;
}

function diagnosticText(entries) {
  return entries.map((entry) => {
    const purpose = t(diagnosticPurpose(entry.url));
    return [
      `${purpose} · ${diagnosticStamp(entry)}`,
      diagnosticPeerName(entry.peer),
      entry.url || "",
      "",
      t("Richiesta"),
      JSON.stringify(entry.request, null, 2),
      "",
      t("Risposta"),
      JSON.stringify(entry.response, null, 2),
    ].join("\n");
  }).join("\n\n---\n\n");
}

function downloadDiagnosticFile(filename, type, content) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function renderDiagnostics(entries) {
  const box = document.getElementById("diagnostic-log");
  if (!box) return;
  const ordered = [...(entries || [])].reverse();
  diagnosticEntries = ordered;
  if (!ordered.length) {
    box.innerHTML = `<p class="mb-0">${t("Nessuno scambio registrato.")}</p>`;
    renderDiagnosticNav([]);
    syncDiagnosticToolbar();
    return;
  }
  box.replaceChildren();
  const items = [];
  ordered.forEach((entry, index) => {
    const purpose = diagnosticPurpose(entry.url);
    const anchor = `exchange-${index + 1}`;
    const article = document.createElement("article");
    article.className = "diagnostic-exchange border-bottom py-3";
    const headingRow = document.createElement("div");
    headingRow.className = "diagnostic-exchange-heading";
    const choice = document.createElement("label");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "diagnostic-select-input";
    checkbox.value = entry.id || "";
    const caption = document.createElement("span");
    caption.className = "visually-hidden";
    caption.textContent = t("Seleziona scambio");
    choice.append(checkbox, caption);
    const heading = document.createElement("h2");
    heading.className = "h5";
    heading.id = anchor;
    heading.textContent = `${t(purpose)} · ${diagnosticStamp(entry)}`;
    headingRow.append(choice, heading);
    const peer = document.createElement("p");
    peer.className = "mb-1";
    peer.textContent = diagnosticPeerName(entry.peer);
    const url = document.createElement("p");
    url.className = "mb-2 long-text";
    url.textContent = entry.url || "";
    article.append(headingRow, peer, url, diagnosticBlock(t("Richiesta"), entry.request), diagnosticBlock(t("Risposta"), entry.response));
    box.appendChild(article);
    items.push({ id: anchor, purpose, label: diagnosticStamp(entry), failed: diagnosticFailed(entry) });
  });
  renderDiagnosticNav(items);
  syncDiagnosticToolbar();
}

async function removeSelectedDiagnostics() {
  const ids = [...document.querySelectorAll(".diagnostic-select-input:checked")].map((box) => box.value).filter(Boolean);
  if (!ids.length) return;
  const headers = { "Content-Type": "application/json" };
  if (typeof SESSION_ID !== "undefined" && SESSION_ID) headers["X-Correlation-ID"] = SESSION_ID;
  const response = await fetch("/itwallet/diagnostics", { method: "DELETE", headers, body: JSON.stringify({ ids }) });
  const data = await response.json().catch(() => ({}));
  if (response.ok && data.success) renderDiagnostics(data.data || []);
}

document.getElementById("diagnostic-log")?.addEventListener("change", (event) => {
  if (event.target.classList.contains("diagnostic-select-input")) syncDiagnosticToolbar();
});

document.getElementById("diagnostic-select-all")?.addEventListener("change", (event) => {
  document.querySelectorAll(".diagnostic-select-input").forEach((box) => {
    box.checked = event.target.checked;
  });
  syncDiagnosticToolbar();
});

document.getElementById("diagnostic-remove")?.addEventListener("click", () => {
  removeSelectedDiagnostics();
});

document.getElementById("diagnostic-export-text")?.addEventListener("click", () => {
  downloadDiagnosticFile("scambi-http.txt", "text/plain;charset=utf-8", diagnosticText(diagnosticEntries));
});

document.getElementById("diagnostic-export-json")?.addEventListener("click", () => {
  downloadDiagnosticFile("scambi-http.json", "application/json;charset=utf-8", JSON.stringify(diagnosticEntries, null, 2));
});

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

document.getElementById("issuer-discovery")?.addEventListener("change", syncDiscoveryMode);
syncTrustAnchor();

document.getElementById("issuer-catalog-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (discoveryValue() === "eudiw-lotl") {
    syncDiscoveryMode();
    return;
  }
  setDiscoveryError("");
  const input = document.getElementById("issuer-url");
  const issuerUrl = input?.value?.trim() || "";
  if (!issuerUrl) {
    setIssuerUrlError(t("Inserisci un URL http o https."));
    return;
  }
  setIssuerUrlError("");
  const response = await executeFetch("/itwallet/issuerCatalog", "POST", {
    issuerUrl,
    discovery: discoveryValue(),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.success) {
    const message = data.message || t("Impossibile leggere i metadata di questo issuer.");
    if (data.field === "discovery") setDiscoveryError(message);
    else setIssuerUrlError(message);
    return;
  }
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
