(function () {
  document.querySelectorAll(".it-lang-option").forEach(function (option) {
    option.addEventListener("click", function () {
      var lang = option.getAttribute("data-lang") === "en" ? "en" : "it";
      var next = window.location.pathname + window.location.search;
      window.location.assign("/wallet/lang/" + lang + "?next=" + encodeURIComponent(next));
    });
  });
})();
