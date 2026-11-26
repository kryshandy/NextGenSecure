// background.js - service worker MV3 de CoreGuard Browser Shield.
// Flux :
//  1. chaque page chargée -> vérification rapide du domaine par l'hôte natif ("checkUrl") ;
//  2. formulaire de connexion détecté -> nouvelle vérification (avec le signal "mot de passe") + capture de
//     l'onglet analysée par OCR / QR ("analyzeCapture") ;
//  3. page jugée sûre -> l'hôte peut fournir l'identifiant du coffre ("requestCredential") ; page suspecte ->
//     bandeau d'alerte et AUCUN auto-remplissage.
// Aucun port réseau : tout passe par Native Messaging (stdin/stdout) vers l'hôte local.

"use strict";

const NOM_HOTE = "com.coreguard.host";
const RANG = { Safe: 0, Suspicious: 1, Phishing: 2 };
const etats = new Map(); // tabId -> { verdict, reasons, url, hasPassword }

function appelerHote(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NOM_HOTE, message, (reponse) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(reponse);
    });
  });
}

function pire(a, b) {
  return (RANG[b] ?? 0) > (RANG[a] ?? 0) ? b : a;
}

// Fusionne un résultat de l'hôte dans l'état de l'onglet, met à jour le badge et prévient la page si besoin
async function appliquer(tabId, url, reponse) {
  if (!reponse || typeof reponse.verdict !== "string") return;
  const precedent = etats.get(tabId);
  const memePage = precedent && precedent.url === url;
  const verdict = memePage ? pire(precedent.verdict, reponse.verdict) : reponse.verdict;
  const reasons = [...(memePage ? precedent.reasons : []), ...(Array.isArray(reponse.reasons) ? reponse.reasons : [])];
  etats.set(tabId, { verdict, reasons: [...new Set(reasons)].slice(0, 6), url, hasPassword: memePage && precedent.hasPassword });

  const alerte = verdict !== "Safe";
  chrome.action.setBadgeText({ tabId, text: alerte ? "!" : "" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: verdict === "Phishing" ? "#c0392b" : "#d68910" });
  if (alerte) {
    try {
      await chrome.tabs.sendMessage(tabId, { type: "warn", verdict, reasons: etats.get(tabId).reasons });
    } catch { /* page sans content script (chrome://, PDF...) */ }
  }
}

async function verifierUrl(tab, hasPassword) {
  if (!tab.url || !/^https?:/.test(tab.url)) return;
  const reponse = await appelerHote({ type: "checkUrl", url: tab.url, hasPassword: !!hasPassword });
  await appliquer(tab.id, tab.url, reponse);
}

async function analyserOnglet(tab) {
  const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  const reponse = await appelerHote({ type: "analyzeCapture", url: tab.url, imageBase64: dataUrl.split(",")[1] });
  await appliquer(tab.id, tab.url, reponse);
}

// Remplissage : uniquement si la page n'est pas suspecte ; l'hôte refuse aussi de lui-même les domaines douteux
async function remplir(tab) {
  const etat = etats.get(tab.id);
  if (etat && etat.verdict !== "Safe") return { ok: false, message: "Page suspecte : remplissage refusé." };
  const reponse = await appelerHote({ type: "requestCredential", url: tab.url });
  if (!reponse || reponse.found !== true) {
    return { ok: false, message: reponse && reponse.blocked ? "Domaine douteux : remplissage refusé."
      : reponse && reponse.locked ? "Coffre CoreGuard verrouillé : déverrouillez-le dans l'application."
      : "Aucun identifiant enregistré pour ce site." };
  }
  await chrome.tabs.sendMessage(tab.id, { type: "autofill", username: reponse.username, password: reponse.password });
  return { ok: true, message: `Identifiant rempli (${reponse.username}).` };
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete") verifierUrl(tab, false).catch((e) => console.warn("CoreGuard :", e.message));
});
chrome.tabs.onRemoved.addListener((tabId) => etats.delete(tabId));

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;

  // Depuis un content script : formulaire de connexion détecté
  if (sender.tab && message && message.type === "loginFormDetected") {
    const tab = sender.tab;
    const etat = etats.get(tab.id);
    if (etat && etat.url === tab.url) etat.hasPassword = true;
    verifierUrl(tab, true)
      .then(() => analyserOnglet(tab))
      .catch((e) => console.warn("CoreGuard :", e.message));
    return;
  }

  // Depuis la fenêtre de l'extension (popup)
  if (!sender.tab && message && message.type === "popupState") {
    chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
      sendResponse({ url: tab && tab.url, etat: tab ? etats.get(tab.id) || null : null });
    });
    return true; // réponse asynchrone
  }
  if (!sender.tab && message && message.type === "popupFill") {
    chrome.tabs.query({ active: true, currentWindow: true })
      .then(([tab]) => (tab ? remplir(tab) : { ok: false, message: "Aucun onglet actif." }))
      .then(sendResponse)
      .catch((e) => sendResponse({ ok: false, message: "Hôte CoreGuard injoignable : " + e.message }));
    return true;
  }
});
