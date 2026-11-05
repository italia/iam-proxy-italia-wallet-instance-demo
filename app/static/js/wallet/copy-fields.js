const COPY_FIELD_SELECTOR = "pre, textarea, .long-text";

function copyFieldText(node) {
  if (node instanceof HTMLTextAreaElement || node instanceof HTMLInputElement) return node.value;
  return node.innerText || "";
}

async function writeClipboard(value) {
  try {
    await navigator.clipboard.writeText(value);
  } catch (error) {
    const area = document.createElement("textarea");
    area.value = value;
    area.dataset.copyIgnore = "true";
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
  }
}

function attachCopyField(node) {
  if (!(node instanceof HTMLElement) || node.dataset.copyIgnore || node.dataset.copyReady || node.closest(".copy-field")) return;
  const isField = node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement;
  if (!isField && !copyFieldText(node).trim()) return;
  node.dataset.copyReady = "true";
  const wrap = document.createElement("div");
  wrap.className = node instanceof HTMLInputElement ? "copy-field copy-field-input" : "copy-field";
  node.replaceWith(wrap);
  wrap.append(node);
  const button = document.createElement("button");
  button.type = "button";
  button.className = "copy-field-button";
  button.setAttribute("aria-label", t("Copia"));
  const sprite = document.body.dataset.iconSprite || "";
  button.innerHTML = `<svg class="icon" aria-hidden="true"><use href="${sprite}#it-copy"></use></svg>`;
  button.addEventListener("click", async () => {
    await writeClipboard(copyFieldText(node));
    button.classList.add("is-copied");
    button.setAttribute("aria-label", t("Copiato"));
    window.setTimeout(() => {
      button.classList.remove("is-copied");
      button.setAttribute("aria-label", t("Copia"));
    }, 1500);
  });
  wrap.append(button);
}

function scanCopyFields(root) {
  const scope = root instanceof HTMLElement || root instanceof Document ? root : document;
  scope.querySelectorAll(COPY_FIELD_SELECTOR).forEach(attachCopyField);
  if (scope instanceof HTMLElement && scope.matches(COPY_FIELD_SELECTOR)) attachCopyField(scope);
}

document.addEventListener("DOMContentLoaded", () => {
  scanCopyFields(document);
  const observer = new MutationObserver((records) => {
    records.forEach((record) => {
      record.addedNodes.forEach((node) => {
        if (node instanceof HTMLElement) scanCopyFields(node);
      });
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });
});
