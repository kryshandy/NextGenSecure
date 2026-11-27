// blocked.js - page d'interception : affiche l'état de l'onglet tenu par le service worker et transmet le choix.
"use strict";

const msg = document.getElementById("msg");

function choisir(choix) {
  msg.textContent = choix === "trust" ? "Confirmez dans la fenêtre CoreGuard…" : "";
  chrome.runtime.sendMessage({ type: "userChoice", choice: choix }, (r) => {
    if (r && !r.ok && r.message) msg.textContent = r.message;
  });
}

chrome.runtime.sendMessage({ type: "blockedState" }, (etat) => {
  if (!etat) {
    msg.textContent = "Analyse expirée : fermez cet onglet.";
    return;
  }
  document.getElementById("url").textContent = etat.url || "";
  const liste = document.getElementById("raisons");
  for (const r of etat.reasons || []) {
    const li = document.createElement("li");
    li.textContent = String(r);
    liste.appendChild(li);
  }
  if (etat.explanation) {
    document.getElementById("ia").hidden = false;
    document.getElementById("iaTexte").textContent = String(etat.explanation);
  }
});

document.getElementById("quitter").addEventListener("click", (e) => { if (e.isTrusted) choisir("leave"); });
document.getElementById("confiance").addEventListener("click", (e) => { if (e.isTrusted) choisir("trust"); });
document.getElementById("continuer").addEventListener("click", (e) => { if (e.isTrusted) choisir("continue"); });
