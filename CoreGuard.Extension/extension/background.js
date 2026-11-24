// background.js - service worker MV3.
// Flux : formulaire de connexion détecté -> capture de l'onglet -> hôte natif (OCR anti-phishing).

"use strict";

const NOM_HOTE = "com.coreguard.host";

// Envoie un message à l'hôte natif et renvoie sa réponse (une requête = un processus hôte).
function appelerHote(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NOM_HOTE, message, (reponse) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(reponse);
      }
    });
  });
}

// Affiche le résultat dans le badge de l'extension (aucun contenu de page n'est réinjecté).
function afficherVerdict(tabId, verdict) {
  const alerte = verdict === "Phishing" || verdict === "Suspicious";
  chrome.action.setBadgeText({ tabId, text: alerte ? "!" : "" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#c0392b" });
}

async function analyserOnglet(tab) {
  // Capture de la zone visible de l'onglet (nécessite activeTab/tabs).
  const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  const reponse = await appelerHote({
    type: "analyzeCapture",
    url: tab.url,
    imageBase64: dataUrl.split(",")[1],
  });
  if (reponse && typeof reponse.verdict === "string") {
    afficherVerdict(tab.id, reponse.verdict);
  }
  return reponse;
}

// Demande d'identifiant à l'hôte puis injection dans la page via le content script.
async function demanderIdentifiant(tab) {
  const reponse = await appelerHote({ type: "requestCredential", url: tab.url });
  if (reponse && reponse.found === true) {
    await chrome.tabs.sendMessage(tab.id, {
      type: "autofill",
      username: reponse.username,
      password: reponse.password,
    });
  }
}

chrome.runtime.onMessage.addListener((message, sender) => {
  // Seuls nos propres content scripts, dans un onglet, sont acceptés.
  if (sender.id !== chrome.runtime.id || !sender.tab) return;
  if (message && message.type === "loginFormDetected") {
    analyserOnglet(sender.tab)
      .then(() => demanderIdentifiant(sender.tab))
      .catch((e) => console.warn("CoreGuard :", e.message));
  }
});
