function markCurrentCredential() {
  const hash = window.location.hash;
  if (!hash.startsWith("#credential-")) return;
  const link = document.querySelector(`#credential-nav a[href="${hash}"]`);
  if (!link) return;
  link.setAttribute("aria-current", "true");
}

markCurrentCredential();

document.getElementById("credential-persistence-dismiss")?.addEventListener("click", () => {
  localStorage.setItem("wallet-hide-credential-persistence", "1");
  document.documentElement.classList.add("hide-credential-persistence");
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
