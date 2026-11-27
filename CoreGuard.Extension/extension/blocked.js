// blocked.js - page d'interception : affiche l'état de l'onglet tenu par le service worker et transmet le choix.
"use strict";

const msg = document.getElementById("msg");

function choisir(choix) {
  msg.textContent = choix === "trust" ? "Confirmez dans la fenêtre CoreGuard…" : "";
  chrome.runtime.sendMessage({ type: "userChoice", choice: choix }, (r) => {
    if (r && !r.ok && r.message) msg.textContent = r.message;
  });
}

function afficher(etat) {
  if (!etat) {
    msg.textContent = "Analyse expirée : fermez cet onglet.";
    return;
  }
  document.getElementById("url").textContent = etat.url || "";
  const liste = document.getElementById("raisons");
  liste.textContent = "";
  for (const r of etat.reasons || []) {
    const li = document.createElement("li");
    li.textContent = String(r);
    liste.appendChild(li);
  }
  if (etat.explanation) {
    document.getElementById("ia").hidden = false;
    document.getElementById("iaTexte").textContent = String(etat.explanation);
  }
}

// L'avis de l'IA locale peut arriver après l'interception : l'état est relu pendant une minute
let relectures = 0;
function relire() {
  chrome.runtime.sendMessage({ type: "blockedState" }, (etat) => {
    afficher(etat);
    if (etat && !etat.explanation && ++relectures < 30) setTimeout(relire, 2000);
  });
}
relire();

document.getElementById("quitter").addEventListener("click", (e) => { if (e.isTrusted) choisir("leave"); });
document.getElementById("confiance").addEventListener("click", (e) => { if (e.isTrusted) choisir("trust"); });
document.getElementById("continuer").addEventListener("click", (e) => { if (e.isTrusted) choisir("continue"); });
