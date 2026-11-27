// background.js - service worker MV3 de CoreGuard Browser Shield.
// Cascade (voir SiteAnalyzer côté hôte) :
//  1. chaque navigation -> "checkUrl" : site de confiance / liste noire / domaine connu / règles d'URL ;
//     liste noire ou phishing -> page d'interception AVANT que l'utilisateur ne saisisse quoi que ce soit ;
//  2. formulaire de connexion sur un site non connu -> capture de l'onglet, OCR + QR ("analyzeCapture") ;
//  3. zone grise -> "reviewSite" : l'IA locale de CoreGuard relit les faits et peut seulement AGGRAVER le verdict ;
//  4. phishing -> page d'interception ; doute -> fenêtre dans la page ; l'utilisateur seul peut faire confiance,
//     et CoreGuard lui demande de le confirmer dans l'application ("trustSite").
// Aucun port réseau : tout passe par Native Messaging (stdin/stdout) vers l'hôte local.

"use strict";

const NOM_HOTE = "com.coreguard.host";
const RANG = { Safe: 0, Suspicious: 1, Phishing: 2 };
const PAGE_BLOCAGE = chrome.runtime.getURL("blocked.html");
const etats = new Map();       // tabId -> { verdict, reasons, url, hasPassword, explanation, trust }
const contournements = new Map(); // tabId -> URL que l'utilisateur a choisi d'ouvrir malgré l'alerte (une fois)

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

// Fusionne un résultat de l'hôte dans l'état de l'onglet, met à jour le badge et prévient la page ou l'intercepte
async function appliquer(tabId, url, reponse) {
  if (!reponse || typeof reponse.verdict !== "string") return;
  const precedent = etats.get(tabId);
  const memePage = precedent && precedent.url === url;
  // Site de confiance (décision de l'utilisateur) : seul cas où le verdict peut redescendre
  const verdict = reponse.trust === "UserTrusted" ? "Safe" : memePage ? pire(precedent.verdict, reponse.verdict) : reponse.verdict;
  const reasons = [...(memePage ? precedent.reasons : []), ...(Array.isArray(reponse.reasons) ? reponse.reasons : [])];
  const explanation = typeof reponse.explanation === "string" ? reponse.explanation : memePage ? precedent.explanation : null;
  etats.set(tabId, {
    verdict, url, explanation,
    reasons: [...new Set(reasons)].slice(0, 6),
    hasPassword: memePage && precedent.hasPassword,
    trust: reponse.trust || (memePage ? precedent.trust : null),
  });

  const alerte = verdict !== "Safe";
  chrome.action.setBadgeText({ tabId, text: alerte ? "!" : "" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: verdict === "Phishing" ? "#c0392b" : "#d68910" });
  if (!alerte) return;

  if (verdict === "Phishing" && contournements.get(tabId) !== url) {
    await chrome.tabs.update(tabId, { url: PAGE_BLOCAGE + "#" + tabId });
    return;
  }
  try {
    await chrome.tabs.sendMessage(tabId, { type: "warn", verdict, reasons: etats.get(tabId).reasons, explanation });
  } catch { /* page sans content script (chrome://, PDF...) */ }
}

async function verifierUrl(tabId, url, hasPassword) {
  if (!url || !/^https?:/.test(url)) return null;
  const reponse = await appelerHote({ type: "checkUrl", url, hasPassword: !!hasPassword });
  await appliquer(tabId, url, reponse);
  return reponse;
}

async function analyserOnglet(tab) {
  const dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
  const etat = etats.get(tab.id);
  const motDePasse = !!(etat && etat.url === tab.url && etat.hasPassword);
  const reponse = await appelerHote({ type: "analyzeCapture", url: tab.url, imageBase64: dataUrl.split(",")[1], hasPassword: motDePasse });
  await appliquer(tab.id, tab.url, reponse);

  // Zone grise : l'IA locale de CoreGuard relit les faits (elle ne peut qu'aggraver le verdict)
  if (reponse && reponse.review) {
    const revue = await appelerHote({ type: "reviewSite", facts: reponse.review });
    if (revue && revue.ok) await appliquer(tab.id, tab.url, revue);
  }
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

// Choix de l'utilisateur (fenêtre de doute dans la page ou page d'interception)
async function choixUtilisateur(tabId, choix) {
  const etat = etats.get(tabId);
  if (!etat) return { ok: false, message: "Page inconnue." };
  if (choix === "leave") {
    await chrome.tabs.update(tabId, { url: "chrome://newtab/" }).catch(() => chrome.tabs.remove(tabId));
    return { ok: true };
  }
  if (choix === "continue") {
    contournements.set(tabId, etat.url);
    await chrome.tabs.update(tabId, { url: etat.url });
    return { ok: true };
  }
  if (choix === "trust") {
    const reponse = await appelerHote({ type: "trustSite", url: etat.url });
    if (reponse && reponse.accepted) {
      etats.delete(tabId);
      await chrome.tabs.update(tabId, { url: etat.url });
      return { ok: true };
    }
    return { ok: false, message: reponse && reponse.unavailable
      ? "Ouvrez CoreGuard pour confirmer (l'application doit tourner)."
      : "Confiance non confirmée dans CoreGuard." };
  }
  return { ok: false, message: "Choix inconnu." };
}

// Vérification dès le début du chargement : l'interception arrive avant toute saisie
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status !== "loading" || !tab.url || tab.url.startsWith(PAGE_BLOCAGE)) return;
  verifierUrl(tabId, tab.url, false).catch((e) => console.warn("CoreGuard :", e.message));
});
chrome.tabs.onRemoved.addListener((tabId) => { etats.delete(tabId); contournements.delete(tabId); });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !message) return;
  const depuisPageBlocage = typeof sender.url === "string" && sender.url.startsWith(PAGE_BLOCAGE);

  // Page d'interception : état de l'onglet et choix de l'utilisateur
  if (depuisPageBlocage && sender.tab) {
    if (message.type === "blockedState") {
      sendResponse(etats.get(sender.tab.id) || null);
      return;
    }
    if (message.type === "userChoice") {
      choixUtilisateur(sender.tab.id, message.choice).then(sendResponse)
        .catch((e) => sendResponse({ ok: false, message: "Hôte CoreGuard injoignable : " + e.message }));
      return true;
    }
    return;
  }

  // Depuis un content script
  if (sender.tab && message.type === "loginFormDetected") {
    const tab = sender.tab;
    const etat = etats.get(tab.id);
    if (etat && etat.url === tab.url) etat.hasPassword = true;
    verifierUrl(tab.id, tab.url, true)
      .then((r) => {
        const e = etats.get(tab.id);
        if (e && e.url === tab.url) e.hasPassword = true;
        return r && r.needsCapture ? analyserOnglet(tab) : null;
      })
      .catch((e) => console.warn("CoreGuard :", e.message));
    return;
  }
  if (sender.tab && message.type === "pageReady") {
    const etat = etats.get(sender.tab.id);
    if (etat && etat.url === sender.tab.url && etat.verdict !== "Safe") {
      chrome.tabs.sendMessage(sender.tab.id, { type: "warn", verdict: etat.verdict, reasons: etat.reasons, explanation: etat.explanation })
        .catch(() => {});
    }
    return;
  }
  if (sender.tab && message.type === "userChoice") {
    choixUtilisateur(sender.tab.id, message.choice).then(sendResponse)
      .catch((e) => sendResponse({ ok: false, message: "Hôte CoreGuard injoignable : " + e.message }));
    return true;
  }

  // Depuis la fenêtre de l'extension (popup)
  if (!sender.tab && message.type === "popupState") {
    chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
      sendResponse({ url: tab && tab.url, etat: tab ? etats.get(tab.id) || null : null });
    });
    return true; // réponse asynchrone
  }
  if (!sender.tab && message.type === "popupAnalyze") {
    chrome.tabs.query({ active: true, currentWindow: true })
      .then(async ([tab]) => {
        if (!tab || !/^https?:/.test(tab.url || "")) return { ok: false, message: "Page non analysable." };
        await analyserOnglet(tab);
        const etat = etats.get(tab.id) || null;
        return { ok: true, url: tab.url, etat, message: etat && etat.verdict === "Safe" ? "Analyse terminée : rien de suspect." : "Analyse terminée." };
      })
      .then(sendResponse)
      .catch((e) => sendResponse({ ok: false, message: "Analyse impossible : " + e.message }));
    return true;
  }
  if (!sender.tab && message.type === "popupFill") {
    chrome.tabs.query({ active: true, currentWindow: true })
      .then(([tab]) => (tab ? remplir(tab) : { ok: false, message: "Aucun onglet actif." }))
      .then(sendResponse)
      .catch((e) => sendResponse({ ok: false, message: "Hôte CoreGuard injoignable : " + e.message }));
    return true;
  }
});
