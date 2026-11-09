// --- STATO DELL'APPLICAZIONE ---
let lastOpenedButtonId = null;
let selectedValue = null;
let credentialsPresenting = null;

// --- RIFERIMENTI DOM: ICONE E POPUP GENERALI ---
const trashIcon = document.querySelector(".trash-icon");
const trashPopup = document.getElementById("trash-popup");
const trashPopupConfirm = document.getElementById("trash-popup-confirm-btn");
const trashPopupCancel = document.getElementById("trash-popup-cancel-btn");

// --- RIFERIMENTI DOM: MODALE DETTAGLI E POPUP CREDENZIALI ---
const template = document.getElementById("detail_template");
const credPopup = document.getElementById("cred-popup");
const credPopupTitle = document.getElementById("cred-popup-title");
const credPopupBody = document.getElementById("cred-popup-body");

const result = document.getElementById("result");
const spinner = document.getElementById("overlay");