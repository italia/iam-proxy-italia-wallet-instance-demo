// --- STATO DELL'APPLICAZIONE ---
let popupHtml;
let lastOpenedButtonId = null;
let selectedValue = null;
let credentialsPresenting = null;
let rp_clientId = "";
let rp_requestUri = "";
let rp_requestUriMethod = "get";
let rp_state = "";

// --- COSTANTI DI SESSIONE E CONFIGURAZIONI ---
//const SESSION_ID = "{{ session_id }}";
//const INIT_ERROR_MESSAGE = "{{ init_error_message|escape }}";

// --- RIFERIMENTI DOM: ICONE E POPUP GENERALI ---
const memoryIcon = document.querySelector(".memory-icon");
const trashIcon = document.querySelector(".trash-icon");
const trashPopup = document.getElementById("trash-popup");
const trashPopupConfirm = document.getElementById("trash-popup-confirm-btn");
const trashPopupCancel = document.getElementById("trash-popup-cancel-btn");

// --- RIFERIMENTI DOM: MODALE DETTAGLI E POPUP CREDENZIALI ---
const template = document.getElementById("detail_template");
const credPopup = document.getElementById("cred-popup");
const credPopupTitle = document.getElementById("cred-popup-title");
const credPopupBody = document.getElementById("cred-popup-body");
const credPopupClose = document.getElementById("cred-popup-close");
const credPopupTrash = document.getElementById("cred-popup-trash");

// --- RIFERIMENTI DOM: ELEMENTI DI CONTROLLO E UI ---
const statesDiv = document.getElementById("states");
const idpDiv = document.getElementById("idp");
const credentialsBtnDiv = document.getElementById("credentials");
const initBtn = document.getElementById("init-btn");
const addBtn = document.getElementById("add-btn");
const rpBtn = document.getElementById("rp-btn");
const deleteBtn = document.getElementById("delete-btn");
const result = document.getElementById("result");
const spinner = document.getElementById("overlay");
const selectElement = document.querySelector('#select');