  /**
   * Esegue una chiamata fetch con intestazione X-Correlation-ID
   * @param {string} url - endpoint da chiamare
   * @param {string} method - GET, POST, PUT, DELETE
   * @param {Object|null} body - dati JSON opzionali per il body
   */
  async function executeFetch(url, method = "GET", body = null) {
    const headers = { "Content-Type": "application/json" };
    if (typeof SESSION_ID !== "undefined" && SESSION_ID) headers["X-Correlation-ID"] = SESSION_ID;
    const options = {
      method: method,
      headers: headers
    };

    // Aggiunge il body solo se non è GET e se body è valorizzato
    if (body && method.toUpperCase() !== "GET") {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    if (!String(url).includes("/itwallet/diagnostics") && typeof refreshDiagnostics === "function") {
      refreshDiagnostics();
    }
    return response;
  }

function syntaxHighlight(json) {
  if (typeof json != 'string') {
    json = JSON.stringify(json, undefined, 2);
  }
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(true|false|null)\b|\b-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?\b)/g, function (match) {
    let cls = 'number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'key';
      } else {
        cls = 'string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'boolean';
    } else if (/null/.test(match)) {
      cls = 'null';
    }
    return '<span class="' + cls + '">' + match + '</span>';
  });
}

function tagCredenziale(value) {
    /*
      Ritorna il tag della credenziale in base al suo credential_id.
      Rimuove il prefisso e nella parte restante applica questa regola:
        - Controlla il primo carattere, se è speciale (non lettera o numero), lo rimuove.
        - Se ci sono almeno 3 lettere maiuscole, restituisce i primi 3.
        - Altrimenti, restituisce i primi 3 caratteri della stringa originale in maiuscolo.
    */

    if (!value) {
        return "N/A";
    }

    const JWT_PREFIX = "jwt";
    const SD_JWT_PREFIX = "dc_sd_jwt";
    const MSO_MDOC_PREFIX = "mso_mdoc";

    const prefixes = [JWT_PREFIX, SD_JWT_PREFIX, MSO_MDOC_PREFIX];

    let valueLower = value.toLowerCase();
    let valueWithoutPrefix = value;

    for (const prefix of prefixes) {
        if (valueLower.startsWith(prefix.toLowerCase())) {
            valueWithoutPrefix = value.slice(prefix.length);
            break;
        }
    }

    // Rimuovi primo carattere se speciale
    if (valueWithoutPrefix && !/^[a-z0-9]/i.test(valueWithoutPrefix[0])) {
        valueWithoutPrefix = valueWithoutPrefix.slice(1);
    }

    // Prendi solo maiuscole
    const uppercaseChars = [...valueWithoutPrefix].filter(char => char === char.toUpperCase() && /[A-Z]/.test(char)).join('');

    if (uppercaseChars.length >= 3) {
        return uppercaseChars.slice(0, 3);
    } else {
        // Cerca underscore non all'inizio
        if (valueWithoutPrefix.indexOf("_", 1) !== -1) { // underscore non all'inizio
            const parts = valueWithoutPrefix.split("_", 2); // Estrae parte dopo underscore
            if (parts[1]) { // esiste qualcosa dopo l'underscore
                return parts[0].slice(0, 3).toUpperCase() + "-" + parts[1][0].toUpperCase(); 
                // limita a tre caratteri prima dell’underscore e accoda la prima lettera dopo l’underscore rendendola maiuscola.
            }
        }

        return valueWithoutPrefix.slice(0, 3).toUpperCase();
    }
}

function formatCredenziale(value) {
    /*
      Ritorna il formato della credenziale in base al suo credential_id.
    */
    if (!value) return t("sconosciuto");
    const prefixes = ["jwt", "dc_sd_jwt", "mso_mdoc"];
    return prefixes.find(p => value.toLowerCase().startsWith(p)) || t("sconosciuto");
}

function createButtonHml(credential_id) {
    const tag = tagCredenziale(credential_id);
    const format = formatCredenziale(credential_id)

    return `
      <span class="cred-format">${format}</span>
      <button id="${credential_id}" class="button-cred" role="button">
        <img src="/static/images/card-violet.svg" alt="${credential_id}">
        <span class="label">${tag}</span>
      </button>
    `;
}

function addButton(credential_id) {
    if (credential_id) {
      const credentialsDiv = document.getElementById("credentials");

      if (credentialsDiv) {
        // Creo un nuovo .cred-item con tag + bottone aggiungi
        const newCredItem = document.createElement("div");
        newCredItem.className = "cred-item";
        newCredItem.innerHTML = createButtonHml(credential_id);

        // Aggiungo il nuovo elemento come ultimo figlio del div
        credentialsDiv.appendChild(newCredItem);
      } else {
        console.warn(`Elemento con id credentials non trovato.`);
      }
    }
}

function deleteButton(credential_id) {
  if (credential_id) {
    const elem = document.getElementById(credential_id);
    if (elem) {
      const containerDiv = elem.parentElement; // il div genitore di span e button
      
      if (containerDiv) {
        containerDiv.remove();  // Rimuove tutto il div, quindi anche span e button dentro
      } else {
        console.warn(`Contenitore genitore non trovato per l'elemento con id ${credential_id}.`);
      }
    } else {
      console.warn(`Elemento con id ${credential_id} non trovato.`);
    }
  }
}

async function confirmViewObjectTypeInMemory() {
  let credPopupBlocked = false;

  if (!selectedValue) return;

  // Mostra spinner durante la richiesta
  credPopupBody.innerHTML = `
    <div class="spinner-wrapper">
      <div class="spinner"></div>
      <p>${t("Richiesta in corso...")}</p>
    </div>
  `;

  try {
    const response = await executeFetch("/itwallet/viewObjectTypeInMemory", "POST", { objectType: selectedValue });

    if (!response.ok) {
      const errorMessage = await getErrorMessage(response);
      throw new Error(`${errorMessage}`);
    }

    const data = await response.json();

    if (data.success) {
      const jsonData = data.data;

      // Caso: nessun oggetto trovato
      if (!jsonData || jsonData.length === 0) {
        throw new Error(`In memoria non è presente alcun ogetto di tipo ${selectedValue}`);
      } 
      
      credPopupBlocked = true;
      let currentIndex = 0;

      function renderJsonObject(index) {
        const obj = jsonData[index];
        const prettyJson = syntaxHighlight(obj);
        const navigator = Array.from({ length: jsonData.length }, (_, i) =>
          `<button class="json-nav-btn" ${i === index ? 'disabled' : ''} onclick="renderJsonObject(${i})">${i + 1}</button>`
        ).join(" ");

        credPopupBody.innerHTML = `
          <div class="custom-confirm-wrapper">
            <div id="json"><pre>${prettyJson}</pre></div>
            <div class="json-navigator">${navigator}</div>
            <div class="button-wrapper">
              <button id="cancelPresentCredential" class="popup-btn cancel" onclick="closeCredPopup()">${t("Annulla")}</button>
            </div>
          </div>
        `;

        credPopupTitle.innerHTML = `${selectedValue}`;

        // Focus e scroll
        const jsonDiv = document.getElementById("json");
        if (jsonDiv) {
          jsonDiv.focus();
          jsonDiv.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }

      // Mettiamo la funzione globale per poterla richiamare dai pulsanti
      window.renderJsonObject = renderJsonObject;

      // Mostra il primo oggetto
      renderJsonObject(currentIndex);
    } else {
      result.innerHTML = `
        <div class="flash-container flash-error">
          <p>${data?.data?.error || t("Impossibile visualizzare l'elemento selezionato")}</p>
        </div>`;
    }

  } catch (err) {
    const message = err?.message || t("Errore sconosciuto");
    result.innerHTML = `
      <div class="flash-container flash-error">
        <p>${message}</p>
      </div>`;
  } finally {
    if (!credPopupBlocked){
      // Chiude il popup in automatico
      setTimeout(() => {
        credPopup.classList.remove("show");
      }, 2000);
    }
  }
}

async function confirmAddCredential() {
    let credPopupBlocked = false;
    
    if (!selectedValue) return;

    // Mostra spinner durante la richiesta
    credPopupBody.innerHTML = `
      <div class="spinner-wrapper">
        <div class="spinner"></div>
        <p>${t("Richiesta in corso...")}</p>
      </div>
    `;

    try {
      const response = await executeFetch("/itwallet/addCredential", "POST", { credentialId: selectedValue });

      if (!response.ok) {
        const errorMessage = await getErrorMessage(response);
        throw new Error(`${errorMessage}`);
      }

      const data = await response.json();

      if (data.success && data.data && data.data.redirect_url) {
        credPopupBody.innerHTML = `
          <p>${t("Ti sto portando all'issuer per scegliere l'identità digitale. Al termine torni qui e l'attestato viene salvato.")}</p>
        `;
        window.location.assign(data.data.redirect_url);
        return;
      }

      if (data.success) {
        let frase = "";

        credentialsPresenting = data.data;

        if (Array.isArray(credentialsPresenting)) {
          credPopupBlocked = true;

          if (credentialsPresenting.length === 0) {
            frase = `<p>${t("Per il rilascio di {name}, non sarà condiviso alcun dato con l'issuer.", { name: `<b>${selectedValue}</b>` })}</p>`;
          } else {
            // Costruiamo i <li> con credenziali e claims
            const descrizioni = credentialsPresenting.map(cred => {
              const nome = `<b>${cred.id}</b> in ${cred.format}`;
              
              const claimsPaths = (cred.claims || [])
                .map(c => c.path?.join("."))
                .filter(Boolean);

              // Se ci sono claims, creo una sottolista <ul> con <li> singoli
              const claimsList = claimsPaths.length > 0
                ? `<ul>` + claimsPaths.map(path => `<li>${path}</li>`).join("") + `</ul>`
                : "";

              return `<li>${nome}${claimsList}</li>`;
            });

            frase = `
              <p>${t("Per il rilascio di {name}, saranno condivisi con l'issuer i seguenti dati:", { name: `<b>${selectedValue}</b>` })}</p>
              <ul style="margin-top: 0px">${descrizioni.join("")}</ul>
              <p>${t("Premendo Continua autorizzi la trasmissione delle informazioni.")}</p>
            `;
          }

          credPopupBody.innerHTML = `
            <div class="custom-confirm-wrapper">
              <div class="confirm-text">${frase}</div>
              <div class="button-wrapper">
                <button id="continuePresentCredential" class="popup-btn confirm" onclick="continueAddCredential()">${t("Continua")}</button>
                <button id="cancelPresentCredential" class="popup-btn cancel" onclick="closeCredPopup()">${t("Annulla")}</button>
              </div>
            </div>`;
        } else {
          result.innerHTML = `
            <div class="alert alert-danger" role="alert">
              <p>${t("La risposta non contiene l'elenco dei dati da condividere.")}</p>
            </div>`;
        }
      } else {
        result.innerHTML = `
          <div class="alert alert-danger" role="alert">
            <p>${data?.data?.error || t("Non riesco a ottenere l'attestato.")}</p>
          </div>`;
      }
    } catch (err) {
      const message = err?.message || t("Errore sconosciuto");
      result.innerHTML = `
        <div class="alert alert-danger" role="alert">
          <p>${message}</p>
        </div>`;
    } finally {
      if (!credPopupBlocked){
        // Chiude il popup in automamtico
        setTimeout(() => {
          credPopup.classList.remove("show");
        }, 2000);
      }
    }
}

async function continueAddCredential(issuanceState) {
  // Mostra spinner durante la richiesta
  credPopupBody.innerHTML = `
    <div class="spinner-wrapper">
      <div class="spinner"></div>
      <p>${t("Richiesta in corso...")}</p>
    </div>
  `;

  try {
    const response = await executeFetch("/itwallet/addCredential/complete", "POST", {
      credentialsPresenting: credentialsPresenting || null,
      issuanceState: typeof issuanceState === "string" ? issuanceState : "",
    });

    if (!response.ok) {
      const errorMessage = await getErrorMessage(response);
      throw new Error(`${errorMessage}`);
    }

    const data = await response.json();

    if (data.success) {
      const credential_id = data?.data?.credential_id;
      const viewUrl = data?.data?.view_url;
      const viewLink = viewUrl
        ? ` <a href="${String(viewUrl).replaceAll('"', "&quot;")}">${t("Visualizzala")}</a>`
        : "";
      const credentialName = String(data?.data?.credential_name || "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
      result.innerHTML = `
        <div class="alert alert-success" role="status">
          <p>${t("Hai appena ottenuto l'attestato {name}.", { name: credentialName })}${viewLink}</p>
        </div>
      `;
      addButton(credential_id);
      if (typeof refreshIssuerCatalog === "function") refreshIssuerCatalog();
      window.obtainNext = true;
    }
    else {
      result.innerHTML = `
        <div class="alert alert-danger" role="alert">
          <p>${data?.data?.error || t("Non riesco a salvare l'attestato.")}</p>
        </div>`;
      if (typeof obtainQueue !== "undefined") obtainQueue = [];
      window.obtainNext = false;
    }
  } catch (err) {
    const message = err?.message || t("Non riesco a salvare l'attestato.");
    result.innerHTML = `
      <div class="alert alert-danger" role="alert">
        <p>${message}</p>
      </div>`;
    if (typeof obtainQueue !== "undefined") obtainQueue = [];
    window.obtainNext = false;
  } finally {
    setTimeout(() => {
      if (credPopup) credPopup.classList.remove("show");
      if (window.obtainNext && typeof obtainQueue !== "undefined" && obtainQueue.length) {
        const nextId = obtainQueue.shift();
        selectedValue = nextId;
        credPopup.classList.add("show");
        confirmAddCredential();
      }
      window.obtainNext = false;
    }, 400);
  }
}

async function loginToRelyingParty() {
  if (!selectedValue) return;

  try {
    const qrCodeContentTextArea = document.getElementById("extra-info");

    // Mostra spinner durante la richiesta
    credPopupBody.innerHTML = `
      <div class="spinner-wrapper">
        <div class="spinner"></div>
        <p>${t("Richiesta in corso...")}</p>
      </div>
    `;

    const response = await executeFetch("/itwallet/loginToRelyingParty", "POST", { relyingPartyId: selectedValue, qrCodeContent: qrCodeContentTextArea.value });

    if (!response.ok) {
      const errorMessage = await getErrorMessage(response);
      throw new Error(`${errorMessage}`);
    }

    const data = await response.json();

    if (data.success) {
      let frase = "";

      credentialsPresenting = data.data;

      if (Array.isArray(credentialsPresenting)) {
        if (credentialsPresenting.length === 0) {
          frase = `<p>${t("Per l'accesso con il verificatore selezionato, non sarà condiviso alcun dato.")}</p>`;
        } else {
          // Costruiamo i <li> con credenziali e claims
          const descrizioni = credentialsPresenting.map(cred => {
            const nome = `<b>${cred.id}</b> in ${cred.format}`;
            
            const claimsPaths = (cred.claims || [])
              .map(c => c.path?.join("."))
              .filter(Boolean);

            // Se ci sono claims, creo una sottolista <ul> con <li> singoli
            const claimsList = claimsPaths.length > 0
              ? `<ul>` + claimsPaths.map(path => `<li>${path}</li>`).join("") + `</ul>`
              : "";

            return `<li>${nome}${claimsList}</li>`;
          });

          frase = `
            <p>${t("Per l'accesso con il verificatore selezionato, saranno condivisi i seguenti dati:")}</p>
            <ul style="margin-top: 0px">${descrizioni.join("")}</ul>
            <p>${t("Premendo Continua autorizzi la trasmissione delle informazioni.")}</p>
          `;
        }

        credPopupBody.innerHTML = `
          <div class="custom-confirm-wrapper">
            <div class="confirm-text">${frase}</div>
            <div class="button-wrapper">
              <button id="continuePresentCredential" class="popup-btn confirm" onclick="loginContinueCredPopup()">${t("Continua")}</button>
              <button id="cancelPresentCredential" class="popup-btn cancel" onclick="closeCredPopup()">${t("Annulla")}</button>
            </div>
          </div>`;
      } else {
        console.error("credentials non è un array!", credentialsPresenting);
        credPopupBody.innerHTML = `
          <div class="flash-container flash-error">
            <p>Credentials non è un array!</p>
          </div>`;
      }
    } else {
      credPopupBody.innerHTML = `
        <div class="flash-container flash-error">
          <p>${data?.data?.error || t("Impossibile effettuare l'accesso")}</p>
        </div>`;
    }
  } catch (err) {
    const message = err?.message || t("Impossibile effettuare l'accesso");
    credPopupBody.innerHTML = `
      <div class="flash-container flash-error">
        <p>${message}</p>
      </div>`;
  }
}

async function loginContinueCredPopup() {
  try {
    
    // Mostra spinner durante la richiesta
    credPopupBody.innerHTML = `
    <div class="spinner-wrapper">
      <div class="spinner"></div>
      <p>${t("Richiesta in corso...")}</p>
    </div>
    `;

    const response = await executeFetch("/itwallet/loginToVerifier/complete", "POST", { credentialsPresenting: credentialsPresenting });

    if (!response.ok) {
      const errorMessage = await getErrorMessage(response);
      throw new Error(`${errorMessage}`);
    }

    const data = await response.json();

    if (data.success) {
      const authorization_response_code = data?.data;
      credPopupBody.innerHTML = `
        <div class="flash-container flash-success">
          <p>${t("Accesso completato.")}</p>
        </div>
      `;
    }
    else {
      credPopupBody.innerHTML = `
        <div class="flash-container flash-error">
          <p>${data?.data?.error || t("Impossibile effettuare l'accesso")}</p>
        </div>`;
    }
  } catch (err) {
    const message = err?.message || t("Impossibile effettuare l'accesso");
    credPopupBody.innerHTML = `
      <div class="flash-container flash-error">
        <p>${message}</p>
      </div>`;
  }
}

function closeCredPopup() {
  if (credPopup) {
    if (!credPopupBody.querySelector('.spinner-wrapper')) {
      credPopup.classList.remove("show");
      credPopup.setAttribute("aria-hidden", "true");
      lastOpenedButtonId=null
      if (typeof obtainQueue !== "undefined") obtainQueue = [];
    }
  }
}

async function deleteCredential() {
  if (credPopup && lastOpenedButtonId) {
    console.log("Ricevuta richiesa rimozione credenziale, id bottone origine:", lastOpenedButtonId);

    const confirmed = confirm(t("Rimuovere l'attestato {name}?", { name: lastOpenedButtonId }));
    
    if (confirmed) {
      // Mostra spinner durante la richiesta
      credPopupBody.innerHTML = `
        <div class="spinner-wrapper">
          <div class="spinner"></div>
          <p>${t("Richiesta in corso...")}</p>
        </div>
      `;

      try {
          const response = await executeFetch("/itwallet/deleteCredential", "POST", { credentialId: lastOpenedButtonId });

          if (!response.ok) {
            const errorMessage = await getErrorMessage(response);
            throw new Error(`${errorMessage}`);
          }

          const data = await response.json();

          if (data.success) {
              const credential_id = data?.data?.credential_id;
              const wallet_initialized = data?.data?.wallet_initialized ?? true;
              const tag = tagCredenziale(credential_id);
              
              // Cancella bottone
              deleteButton(credential_id);

              if (wallet_initialized) {
                result.innerHTML = `
                    <div class="flash-container flash-success">
                      <p>${t("Attestazione {name} rimossa.", { name: tag })}</p>
                    </div>`;
              } 
              else {
                if (trashIcon){
                  trashIcon.hidden = true;
                }

                result.innerHTML = `
                    <div class="flash-container flash-success">
                      <p>${t("Attestazione {name} rimossa. Il wallet è stato reimpostato.", { name: tag })}</p>
                    </div>`;
              }
            }
            else {
              result.innerHTML = `
                <div class="flash-container flash-error">
                  <p>${data?.data?.error || t("Non riesco a eliminare l'attestato.")}</p>
                </div>`;
            }
          } catch (err) {
            const message = err?.message || t("Non riesco a eliminare l'attestato.");
            result.innerHTML = `
              <div class="flash-container flash-error">
                <p>${message}</p>
              </div>`;
          } finally {
            lastOpenedButtonId=null;
            credPopup.classList.remove("show");
          }
    }
  }
}

/**
 * Estrae un messaggio di errore leggibile da una Response fetch.
 * Se il backend risponde con JSON { data: { error, error_description } }
 * lo formatta come stringa. Altrimenti torna il testo grezzo.
 */
async function getErrorMessage(response) {
  try {
    const errorJson = await response.json();
    const err = errorJson?.data?.error || errorJson?.error_message || t("Errore generico");
    const desc = errorJson?.data?.error_description;
    return desc ? `${err} - ${desc}` : err;
  } catch (e) {
    // Non è JSON valido → restituisco il testo grezzo
    return await response.text();
  }
}
