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
    // champ visible : le service worker vérifie l'URL avec le signal « mot de passe » puis capture la page
    dejaSignale = true;
    chrome.runtime.sendMessage({ type: "loginFormDetected" });
  }

  // Alerte (une seule instance, mise à jour si le verdict s'aggrave) :
  //  - « doute » : fenêtre au centre de la page (Quitter / Je fais confiance / Continuer prudemment) ;
  //  - « phishing » ouvert malgré la page d'interception : bandeau rouge permanent en haut.
  // Les boutons n'acceptent que de vrais clics (event.isTrusted) : un script de la page ne peut pas choisir à la place
  // de l'utilisateur ; et « Je fais confiance » doit encore être confirmé dans l'application CoreGuard.
  let hoteAlerte = null;
  function afficherAlerte(verdict, raisons, explication) {
    pageSuspecte = true;
    if (!hoteAlerte) {
      hoteAlerte = document.createElement("coreguard-alerte");
      const racine = hoteAlerte.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = `
        .fond { position: fixed; inset: 0; z-index: 2147483647; background: rgba(10,12,20,.55); display: flex;
                align-items: center; justify-content: center; font: 14px/1.45 "Segoe UI", system-ui, sans-serif; }
        .fond.bandeau { inset: 0 0 auto 0; background: none; display: block; }
        .boite { width: min(520px, 92vw); background: #161a26; color: #e8ebf3; border-radius: 14px; padding: 22px 24px;
                 box-shadow: 0 18px 50px rgba(0,0,0,.45); border-top: 5px solid #d68910; }
        .bandeau .boite { width: auto; border-radius: 0; padding: 10px 16px; border-top: none; background: #b42335; color: #fff;
                 display: flex; gap: 12px; align-items: center; box-shadow: 0 2px 12px rgba(0,0,0,.35); }
        .Phishing .boite { border-top-color: #e5484d; }
        .t { font-size: 18px; font-weight: 700; margin-bottom: 8px; } .bandeau .t { font-size: 14px; margin: 0; }
        ul { margin: 6px 0 0; padding-left: 18px; color: #c5cad8; } .bandeau ul { display: none; }
        .ia { margin-top: 12px; background: #1f2433; border-radius: 8px; padding: 10px 12px; }
        .ia b { display: block; font-size: 12px; color: #9aa3b8; margin-bottom: 2px; } .bandeau .ia { display: none; }
        .msg { margin-top: 10px; color: #ffb4b4; min-height: 1em; } .bandeau .msg { display: none; }
        .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; flex-wrap: wrap; }
        .bandeau .actions { margin: 0 0 0 auto; }
        button { border-radius: 8px; padding: 8px 14px; cursor: pointer; font: inherit; border: 1px solid #39405a;
                 background: #232a3d; color: #e8ebf3; }
        button.principal { background: #e5484d; border-color: #e5484d; color: #fff; font-weight: 600; }`;
      const fond = document.createElement("div");
      const boite = document.createElement("div");
      boite.className = "boite";
      const titre = document.createElement("div");
      titre.className = "t";
      const liste = document.createElement("ul");
      const ia = document.createElement("div");
      ia.className = "ia";
      const iaTitre = document.createElement("b");
      iaTitre.textContent = "Avis de l'IA locale de CoreGuard";
      const iaTexte = document.createElement("span");
      ia.append(iaTitre, iaTexte);
      const msg = document.createElement("div");
      msg.className = "msg";
      const actions = document.createElement("div");
      actions.className = "actions";
      const bouton = (texte, classe, action) => {
        const b = document.createElement("button");
        b.textContent = texte;
        if (classe) b.className = classe;
        b.addEventListener("click", (e) => { if (e.isTrusted) action(); });
        return b;
      };
      const choisir = (choix) => chrome.runtime.sendMessage({ type: "userChoice", choice: choix }, (r) => {
        if (r && !r.ok && r.message) msg.textContent = r.message;
      });
      const quitter = bouton("Quitter la page", "principal", () => choisir("leave"));
      const confiance = bouton("Je fais confiance à ce site", "", () => {
        msg.textContent = "Confirmez dans la fenêtre CoreGuard…";
        choisir("trust");
      });
      const continuer = bouton("Continuer prudemment", "", () => { fond.style.display = "none"; });
      actions.append(continuer, confiance, quitter);
      boite.append(titre, liste, ia, msg, actions);
      fond.append(boite);
      racine.append(style, fond);
      hoteAlerte._parties = { fond, titre, liste, ia, iaTexte, continuer, confiance };
      document.documentElement.appendChild(hoteAlerte);
    }
    const p = hoteAlerte._parties;
    const contourne = verdict === "Phishing";
    p.fond.className = "fond " + verdict + (contourne ? " bandeau" : "");
    p.fond.style.display = contourne ? "block" : "flex";
    p.titre.textContent = contourne
      ? "CoreGuard : site d'arnaque probable, ouvert malgré l'alerte — ne saisissez aucun mot de passe ni code"
      : "CoreGuard doute de ce site";
    p.continuer.textContent = contourne ? "Masquer" : "Continuer prudemment";
    p.confiance.style.display = contourne ? "none" : "";
    p.liste.textContent = "";
    for (const r of (raisons || []).slice(0, 4)) {
      const li = document.createElement("li");
      li.textContent = String(r);
      p.liste.appendChild(li);
    }
    p.ia.style.display = explication && !contourne ? "block" : "none";
    p.iaTexte.textContent = explication ? String(explication) : "";
  }

  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== chrome.runtime.id || !message) return;

    if (message.type === "warn" && (message.verdict === "Phishing" || message.verdict === "Suspicious")) {
      afficherAlerte(message.verdict, message.reasons, message.explanation);
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

  // Page rechargée après « Continuer » : l'état déjà connu est réaffiché
  chrome.runtime.sendMessage({ type: "pageReady" });
  signalerFormulaire();
  new MutationObserver(signalerFormulaire).observe(document.documentElement, { childList: true, subtree: true });
})();
