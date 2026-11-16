function markCurrentCredential() {
  const hash = window.location.hash;
  if (!hash.startsWith("#credential-")) return;
  const link = document.querySelector(`#credential-nav a[href="${hash}"]`);
  if (!link) return;
  link.setAttribute("aria-current", "true");
}

function credentialTimeZone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch (_) {
    return "UTC";
  }
}

function formatCredentialInstant(iso) {
  const value = new Date(iso);
  if (Number.isNaN(value.getTime())) return `${iso} (UTC)`;
  const timeZone = credentialTimeZone();
  try {
    const formatted = new Intl.DateTimeFormat(undefined, {
      dateStyle: "long",
      timeStyle: "short",
      timeZone,
    }).format(value);
    return `${formatted} (${timeZone})`;
  } catch (_) {
    const formatted = new Intl.DateTimeFormat(undefined, {
      dateStyle: "long",
      timeStyle: "short",
      timeZone: "UTC",
    }).format(value);
    return `${formatted} (UTC)`;
  }
}

function renderCredentialInstants() {
  document.querySelectorAll("[data-credential-instant]").forEach((node) => {
    const iso = node.getAttribute("data-credential-instant");
    if (!iso) return;
    node.textContent = formatCredentialInstant(iso);
  });
}

markCurrentCredential();
renderCredentialInstants();

document.getElementById("credential-persistence-dismiss")?.addEventListener("click", () => {
  localStorage.setItem("wallet-hide-credential-persistence", "1");
  document.documentElement.classList.add("hide-credential-persistence");
});

const credentialTrashIcon = document.querySelector(".trash-icon");
const credentialTrashPopup = document.getElementById("trash-popup");
const credentialTrashConfirm = document.getElementById("trash-popup-confirm-btn");
const credentialTrashCancel = document.getElementById("trash-popup-cancel-btn");
const credentialResetError = document.getElementById("credential-reset-error");

credentialTrashIcon?.addEventListener("click", () => {
  if (!credentialTrashPopup) return;
  if (credentialTrashPopup.open) credentialTrashPopup.close();
  else credentialTrashPopup.showModal();
});

credentialTrashCancel?.addEventListener("click", () => credentialTrashPopup?.close());

credentialTrashPopup?.addEventListener("click", (event) => {
  if (event.target === credentialTrashPopup) credentialTrashPopup.close();
});

credentialTrashConfirm?.addEventListener("click", async () => {
  credentialTrashPopup?.close();
  if (credentialResetError) {
    credentialResetError.hidden = true;
    credentialResetError.textContent = "";
  }
  try {
    const response = await fetch("/itwallet/reset");
    if (!response.ok) throw new Error(t("Non riesco a reimpostare il wallet."));
    window.location.reload();
  } catch (error) {
    if (!credentialResetError) return;
    credentialResetError.hidden = false;
    credentialResetError.textContent = error.message;
  }
});

document.querySelector("#credential-nav")?.addEventListener("click", (event) => {
  const link = event.target.closest("a");
  if (!link || !link.getAttribute("href")?.startsWith("#")) return;
  const target = document.querySelector(link.getAttribute("href"));
  if (!target) return;
  event.preventDefault();
  document.querySelectorAll("#credential-nav a[aria-current]").forEach((current) => {
    current.removeAttribute("aria-current");
  });
  link.setAttribute("aria-current", "true");
  target.scrollIntoView({ behavior: "smooth", block: "start" });
  history.replaceState(null, "", link.getAttribute("href"));
});
