  /**
   * Esegue una chiamata fetch con intestazione X-Correlation-ID
   * @param {string} url - endpoint da chiamare
   * @param {string} method - GET, POST, PUT, DELETE
   * @param {Object|null} body - dati JSON opzionali per il body
   */
  async function executeFetch(url, method = "GET", body = null) {
    const options = {
      method: method,
      headers: {
        "X-Correlation-ID": SESSION_ID,
        "Content-Type": "application/json"
      }
    };

    // Aggiunge il body solo se non è GET e se body è valorizzato
    if (body && method.toUpperCase() !== "GET") {
      options.body = JSON.stringify(body);
    }

    // Torna direttamente il Response grezzo
    return await fetch(url, options);
  }

function showTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('.tab[data-tab="'+tabId+'"]').classList.add('active');
  document.getElementById(tabId).classList.add('active');

  const tabContent = document.getElementById(tabId);
  const copyBtn = document.getElementById('copyBtn');

  let hasCode = false;
  const rawText = tabContent.textContent.trim();
  const rawHtml = tabContent.innerHTML.trim();

  // Controllo: se contiene tag HTML
  const hasHtmlTags = /<[^>]+>/.test(rawHtml);  // regex che trova qualunque tag

  // Applica syntaxHighlight se il contenuto è JSON (prova a fare il parsing)
  try {
    const parsed = JSON.parse(rawText);  // Se non è valido, va in catch
    tabContent.innerHTML = '<pre>' + syntaxHighlight(parsed) + '</pre>';
    hasCode = true;
  } catch (e) {
      // Se NON è JSON ma è solo testo senza tag HTML complessi
      if (rawText.length > 0 && !hasHtmlTags) {
        hasCode = true;
      }
  }

  console.log('hasCode:', hasCode);

  // Mostra o nascondi il bottone copy
  if (copyBtn) {
    copyBtn.style.display = hasCode ? 'inline-block' : 'none';
  }
}

function copyActiveTabContent() {
  const activeTab = document.querySelector('.tab-content.active');
  const copyBtn = document.getElementById('copyBtn');
  
  if (activeTab && copyBtn) {
    let textToCopy = activeTab.innerText || activeTab.textContent;
    textToCopy = textToCopy.trim();

    navigator.clipboard.writeText(textToCopy)
      .then(() => {
        copyBtn.textContent = 'Copied';
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
        }, 2000); // Dopo 2 secondi torna a "Copy"
      })
      .catch(err => {
        console.error('Errore nel copiare: ', err);
        copyBtn.textContent = 'Error';
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
        }, 2000);
      });
  }
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
    if (!value) return "sconosciuto";
    const prefixes = ["jwt", "dc_sd_jwt", "mso_mdoc"];
    return prefixes.find(p => value.toLowerCase().startsWith(p)) || "sconosciuto";
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
      <p>Richiesta in corso...</p>
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
              <button id="cancelPresentCredential" class="popup-btn cancel" onclick="closeCredPopup()">Annulla</button>
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
          <p>${data?.data?.error || "Impossibile visualizzare la tipologia di oggetto selezionata"}</p>
        </div>`;
    }

  } catch (err) {
    const message = err?.message || "Errore sconosciuto";
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
        <p>Richiesta in corso...</p>
      </div>
    `;

    try {
      const response = await executeFetch("/itwallet/addCredential", "POST", { credentialId: selectedValue });

      if (!response.ok) {
        const errorMessage = await getErrorMessage(response);
        throw new Error(`${errorMessage}`);
      }

      const data = await response.json();

      if (data.success) {
        let frase = "";

        credentialsPresenting = data.data;

        if (Array.isArray(credentialsPresenting)) {
          credPopupBlocked = true;

          if (credentialsPresenting.length === 0) {
            frase = `<p>Per il rilascio di <b>${selectedValue}</b>, non sarà condiviso alcun dato con l'EAA Provider.</p>`;
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
              <p>Per il rilascio di <b>${selectedValue}</b>, saranno condivisi con l'EAA Provider i seguenti dati:</p>
              <ul style="margin-top: 0px">${descrizioni.join("")}</ul>
              <p>Premendo Continua autorizzi la trasmissione delle informazioni.</p>
            `;
          }

          credPopupBody.innerHTML = `
            <div class="custom-confirm-wrapper">
              <div class="confirm-text">${frase}</div>
              <div class="button-wrapper">
                <button id="continuePresentCredential" class="popup-btn confirm" onclick="continueAddCredential()">Continua</button>
                <button id="cancelPresentCredential" class="popup-btn cancel" onclick="closeCredPopup()">Annulla</button>
              </div>
            </div>`;
        } else {
          console.error("credentials non è un array!", credentialsPresenting);
          result.innerHTML = `
            <div class="flash-container flash-error">
              <p>Credentials non è un array!</p>
            </div>`;
        }
      } else {
        result.innerHTML = `
          <div class="flash-container flash-error">
            <p>${data?.data?.error || "Impossibile aggiungere la credenziale"}</p>
          </div>`;
      }
    } catch (err) {
      const message = err?.message || "Errore sconosciuto";
      result.innerHTML = `
        <div class="flash-container flash-error">
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

async function continueAddCredential() {
  // Mostra spinner durante la richiesta
  credPopupBody.innerHTML = `
    <div class="spinner-wrapper">
      <div class="spinner"></div>
      <p>Richiesta in corso...</p>
    </div>
  `;

  try {
    const response = await executeFetch("/itwallet/addCredential/complete", "POST", { credentialsPresenting: credentialsPresenting });

    if (!response.ok) {
      const errorMessage = await getErrorMessage(response);
      throw new Error(`${errorMessage}`);
    }

    const data = await response.json();

    if (data.success) {
      const credential_id = data?.data?.credential_id;
      const tag = tagCredenziale(credential_id);
      result.innerHTML = `
        <div class="flash-container flash-success">
          <p>Credenziale ${tag} aggiunta con successo!</p>
        </div>
      `;
      // Aggiungi bottone
      addButton(credential_id);
    }
    else {
      result.innerHTML = `
        <div class="flash-container flash-error">
          <p>${data?.data?.error || "Fallita l'elaborazione della richiesta"}</p>
        </div>`;
    }
  } catch (err) {
    const message = err?.message || "Fallita l'elaborazione della richiesta";
    result.innerHTML = `
      <div class="flash-container flash-error">
        <p>${message}</p>
      </div>`;
  } finally {
    // Chiude il popup in automamtico
    setTimeout(() => {
      credPopup.classList.remove("show");
    }, 2000);
  }
}

async function loginToRelyingParty() {
  if (!selectedValue) return;

  try {
    const qrCodeContentTextArea = document.getElementById("extraInfo");

    // Mostra spinner durante la richiesta
    credPopupBody.innerHTML = `
      <div class="spinner-wrapper">
        <div class="spinner"></div>
        <p>Richiesta in corso...</p>
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
          frase = `<p>Per la login con il Relying Party selezionato, non sarà condiviso alcun dato.</p>`;
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
            <p>Per la login con il Relying Party selezionato, saranno condivisi i seguenti dati:</p>
            <ul style="margin-top: 0px">${descrizioni.join("")}</ul>
            <p>Premendo Continua autorizzi la trasmissione delle informazioni.</p>
          `;
        }

        credPopupBody.innerHTML = `
          <div class="custom-confirm-wrapper">
            <div class="confirm-text">${frase}</div>
            <div class="button-wrapper">
              <button id="continuePresentCredential" class="popup-btn confirm" onclick="loginContinueCredPopup()">Continua</button>
              <button id="cancelPresentCredential" class="popup-btn cancel" onclick="closeCredPopup()">Annulla</button>
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
          <p>${data?.data?.error || "Impossibile effettuare il login"}</p>
        </div>`;
    }
  } catch (err) {
    const message = err?.message || "Impossibile effettuare il login";
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
      <p>Richiesta in corso...</p>
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
          <p>Login concluso con successo!</p>
        </div>
      `;
    }
    else {
      credPopupBody.innerHTML = `
        <div class="flash-container flash-error">
          <p>${data?.data?.error || "Impossibile effettuare il login"}</p>
        </div>`;
    }
  } catch (err) {
    const message = err?.message || "Impossibile effettuare il login";
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
      lastOpenedButtonId=null
    }
  }
}

async function deleteCredential() {
  if (credPopup && lastOpenedButtonId) {
    console.log("Ricevuta richiesa rimozione credenziale, id bottone origine:", lastOpenedButtonId);

    const confirmed = confirm(`Sei sicuro di voler rimuovere la credenziale "${lastOpenedButtonId}"?`);
    
    if (confirmed) {
      // Mostra spinner durante la richiesta
      credPopupBody.innerHTML = `
        <div class="spinner-wrapper">
          <div class="spinner"></div>
          <p>Richiesta in corso...</p>
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
                      <p>Credenziale ${tag} rimossa con successo!</p>
                    </div>`;
              } 
              else {
                if (addBtn){
                  // nascondi pulsante aggiungi credenziali
                  addBtn.style.display = "none";
                }

                if (rpBtn){
                  // nascondi pulsante login RP
                  rpBtn.style.display = "none";
                }

                if (credentialsBtnDiv){
                  // nascondi div credenziali
                  credentialsBtnDiv.style.display = "none";
                }

                if (trashIcon){
                  // nascondi icon trash
                  trashIcon.style.display = "none";
                }

                if (statesDiv){
                  // mostra select stato membro
                  statesDiv.style.display = "block";
                  if (selectElement && selectElement.tomselect) {
                    selectElement.tomselect.clear(); // resetta la selezione
                    // mostra initBtn
                    if (initBtn){
                      initBtn.style.display = "inline-flex";
                      initBtn.disabled = true;
                    }
                  }

                  // mostra select stato membro
                  idpDiv.style.display = "block";
                }

                if (idpDiv){
                  // mostra radio button idp
                  idpDiv.style.display = "block";
                }

                result.innerHTML = `
                    <div class="flash-container flash-success">
                      <p>Credenziale ${tag} rimossa con successo ed effettuato il reset del wallet!</p>
                    </div>`;
              }
            }
            else {
              result.innerHTML = `
                <div class="flash-container flash-error">
                  <p>${data?.data?.error || "Fallita l'elaborazione della richiesta"}</p>
                </div>`;
            }
          } catch (err) {
            const message = err?.message || "Fallita l'elaborazione della richiesta";
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
 * Estrae l'host da una URL.
 * @param {string} url - La URL di partenza.
 * @returns {string|null} L'host se valido, altrimenti null.
 */
function getHostFromUrl(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.host;  // include eventuale porta (es. example.com:8080)
    // Se vuoi solo il dominio senza porta, usa:
    // return parsedUrl.hostname;
  } catch (e) {
    console.error("❌ URL non valida:", e);
    return null;
  }
}

function apriQrPopup() {
    const popupWidth = 500;
    const popupHeight = 620;
    //const left = (window.screen.width - popupWidth) / 2;
    //const top = (window.screen.height - popupHeight) / 2;

    const redirectUrl = "/static/qr_code_reader.html";

    const popup = window.open(
      redirectUrl,
      "walletPopup",
      `width=${popupWidth},height=${popupHeight},left=40,top=40,resizable=yes,scrollbars=yes`
    );

    if (!popup || popup.closed || typeof popup.closed === 'undefined') {
      alert("Popup bloccato! Abilita i popup per questo sito.");
      return;
    }

    popup.focus();

    // Aggiungi un event listener temporaneo per click nella pagina principale
    const closeOnClickOutside = (event) => {
        if (popup && !popup.closed) {
            popup.close();
        }

        document.removeEventListener('click', closeOnClickOutside);
    };

    // Ritardo per evitare che il click di apertura venga subito intercettato
    setTimeout(() => {
        document.addEventListener('click', closeOnClickOutside);
    }, 500);
}

function showDegree(degreeId) {
    const links = document.querySelectorAll(".degree-link");
    const details = document.querySelectorAll(".degree-details");

    links.forEach(l => l.classList.remove("active"));
    details.forEach(d => d.style.display = "none");

    document.querySelector(`.degree-link[data-degree='${degreeId}']`).classList.add("active");
    document.querySelector(`.degree-details[data-degree='${degreeId}']`).style.display = "block";
}

/**
 * Estrae un messaggio di errore leggibile da una Response fetch.
 * Se il backend risponde con JSON { data: { error, error_description } }
 * lo formatta come stringa. Altrimenti torna il testo grezzo.
 */
async function getErrorMessage(response) {
  try {
    const errorJson = await response.json();
    const err = errorJson?.data?.error || "Errore generico";
    const desc = errorJson?.data?.error_description;
    return desc ? `${err} - ${desc}` : err;
  } catch (e) {
    // Non è JSON valido → restituisco il testo grezzo
    return await response.text();
  }
}
