// content.js - script injecté dans les pages.
// Rôles : détecter les formulaires de connexion, afficher le bandeau d'alerte anti-phishing, auto-remplir.
// SÉCURITÉ : jamais de presse-papiers ; les données de la page sont NON FIABLES (on ne lit que la présence des
// champs) ; le bandeau vit dans un Shadow DOM fermé (la page ne peut ni le lire ni le masquer par CSS) et son
// texte est inséré avec textContent (aucun HTML interprété).

(function () {
  "use strict";

  let dejaSignale = false;
  let pageSuspecte = false;

  function trouverChampsMotDePasse() {
    return Array.from(document.querySelectorAll('input[type="password"]')).filter((el) => el.offsetParent !== null);
  }

  function trouverChampIdentifiant(champMdp) {
    const formulaire = champMdp.form || document;
    const candidats = Array.from(
      formulaire.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')
    ).filter((el) => el.offsetParent !== null);
    let retenu = null;
    for (const c of candidats) {
      if (c.compareDocumentPosition(champMdp) & Node.DOCUMENT_POSITION_FOLLOWING) retenu = c;
    }
    return retenu;
  }

  function definirValeur(input, valeur) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(input, valeur);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function signalerFormulaire() {
    if (dejaSignale || trouverChampsMotDePasse().length === 0) return;
    dejaSignale = true;
    chrome.runtime.sendMessage({ type: "loginFormDetected" });
  }

  // Bandeau d'alerte (une seule instance, mise à jour si le verdict s'aggrave)
  let hoteBandeau = null;
  function afficherBandeau(verdict, raisons) {
    pageSuspecte = true;
    if (!hoteBandeau) {
      hoteBandeau = document.createElement("coreguard-alerte");
      const racine = hoteBandeau.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = `
        .b { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647; font: 14px/1.4 "Segoe UI", system-ui, sans-serif;
             color: #fff; padding: 12px 16px; display: flex; gap: 12px; align-items: flex-start; box-shadow: 0 2px 12px rgba(0,0,0,.35); }
        .b.Phishing { background: #b42335; } .b.Suspicious { background: #9a5b00; }
        .t { font-weight: 700; margin-bottom: 4px; } ul { margin: 0; padding-left: 18px; }
        button { margin-left: auto; background: rgba(255,255,255,.18); color: #fff; border: 1px solid rgba(255,255,255,.5);
                 border-radius: 6px; padding: 6px 12px; cursor: pointer; font: inherit; }`;
      const boite = document.createElement("div");
      const texte = document.createElement("div");
      const titre = document.createElement("div");
      titre.className = "t";
      const liste = document.createElement("ul");
      const fermer = document.createElement("button");
      fermer.textContent = "J'ai compris";
      fermer.addEventListener("click", () => { boite.style.display = "none"; });
      texte.append(titre, liste);
      boite.append(texte, fermer);
      racine.append(style, boite);
      hoteBandeau._parties = { boite, titre, liste };
      document.documentElement.appendChild(hoteBandeau);
    }
    const { boite, titre, liste } = hoteBandeau._parties;
    boite.className = "b " + verdict;
    boite.style.display = "flex";
    titre.textContent = verdict === "Phishing"
      ? "CoreGuard : page de phishing probable — ne saisissez aucun mot de passe ni code"
      : "CoreGuard : page suspecte — vérifiez l'adresse avant de saisir vos identifiants";
    liste.textContent = "";
    for (const r of (raisons || []).slice(0, 4)) {
      const li = document.createElement("li");
      li.textContent = String(r);
      liste.appendChild(li);
    }
  }

  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id || !message) return;

    if (message.type === "warn" && (message.verdict === "Phishing" || message.verdict === "Suspicious")) {
      afficherBandeau(message.verdict, message.reasons);
      return;
    }

    if (message.type === "autofill" && typeof message.username === "string" && typeof message.password === "string") {
      if (pageSuspecte) return; // double garde : jamais d'identifiant sur une page signalée
      const champMdp = trouverChampsMotDePasse()[0];
      if (!champMdp) return;
      const champId = trouverChampIdentifiant(champMdp);
      if (champId) definirValeur(champId, message.username);
      definirValeur(champMdp, message.password);
    }
  });

  signalerFormulaire();
  new MutationObserver(signalerFormulaire).observe(document.documentElement, { childList: true, subtree: true });
})();
