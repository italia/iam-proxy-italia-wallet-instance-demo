if (template) {
  template.addEventListener("shown.bs.modal", async function (event) {
    const button = event.relatedTarget;
    const button_split = button.id.split(":");
    const input_body = {
      issuer: button_split.slice(0, -1).join(":"),
      key: button_split.pop()
    };
    try {
      const response = await executeFetch("/wallet/detail", "POST", input_body);
      if (!response.ok) throw new Error(await getErrorMessage(response));
      document.getElementById("modal-body-detail").innerHTML = await response.text();
    } catch (err) {
      console.error(err);
    }
  });
}
