// content.js - script injecté dans les pages.
// Rôle : détecter les formulaires de connexion et auto-remplir par injection DOM directe.
// SÉCURITÉ : jamais de presse-papiers (navigator.clipboard / execCommand interdits ici).
// Les données de la page sont NON FIABLES : on ne lit que la présence des champs.

(function () {
  "use strict";

  let dejaSignale = false;

  // Retourne les champs mot de passe visibles de la page.
  function trouverChampsMotDePasse() {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter(
      (el) => el.offsetParent !== null
    );
  }

  // Cherche le champ identifiant le plus proche (champ texte/email précédant le mot de passe).
  function trouverChampIdentifiant(champMdp) {
    const formulaire = champMdp.form || document;
    const candidats = Array.from(
      formulaire.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')
    ).filter((el) => el.offsetParent !== null);
    let retenu = null;
    for (const c of candidats) {
      // Garde le dernier champ situé avant le champ mot de passe dans l'ordre du document.
      if (c.compareDocumentPosition(champMdp) & Node.DOCUMENT_POSITION_FOLLOWING) {
        retenu = c;
      }
    }
    return retenu;
  }

  // Affecte une valeur via le setter natif pour que les frameworks (React...) voient le changement.
  function definirValeur(input, valeur) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(input, valeur);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Signale au service worker l'apparition d'un formulaire de connexion (une fois par page).
  function signalerFormulaire() {
    if (dejaSignale || trouverChampsMotDePasse().length === 0) return;
    dejaSignale = true;
    chrome.runtime.sendMessage({ type: "loginFormDetected", url: location.href });
  }

  // Auto-remplissage : uniquement sur ordre du background (identifiants fournis par l'hôte).
  chrome.runtime.onMessage.addListener((message, sender) => {
    // Refuse tout message ne venant pas de notre propre extension.
    if (sender.id !== chrome.runtime.id) return;
    if (
      message &&
      message.type === "autofill" &&
      typeof message.username === "string" &&
      typeof message.password === "string"
    ) {
      const champMdp = trouverChampsMotDePasse()[0];
      if (!champMdp) return;
      const champId = trouverChampIdentifiant(champMdp);
      if (champId) definirValeur(champId, message.username);
      definirValeur(champMdp, message.password);
    }
  });

  // Détection initiale + surveillance des formulaires injectés dynamiquement (SPA).
  signalerFormulaire();
  new MutationObserver(signalerFormulaire).observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
})();
