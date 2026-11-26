// popup.js - fenêtre de l'extension : verdict de la page active et remplissage à la demande.
"use strict";

const TITRES = {
  Safe: "Aucun signe de phishing détecté",
  Suspicious: "Page suspecte : prudence",
  Phishing: "Phishing probable : ne saisissez rien",
};

function afficher(etat, url) {
  const boite = document.getElementById("verdict");
  const verdict = etat ? etat.verdict : "Unknown";
  boite.className = "verdict " + (TITRES[verdict] ? verdict : "Unknown");
  document.getElementById("titre").textContent = TITRES[verdict] || "Page non analysée (rechargez-la)";
  const liste = document.getElementById("raisons");
  liste.textContent = "";
  for (const r of (etat && etat.reasons) || []) {
    const li = document.createElement("li");
    li.textContent = String(r);
    liste.appendChild(li);
  }
  document.getElementById("url").textContent = url || "";
  document.getElementById("remplir").disabled = !url || !/^https?:/.test(url) || (etat && etat.verdict !== "Safe");
}

chrome.runtime.sendMessage({ type: "popupState" }, (reponse) => {
  if (reponse) afficher(reponse.etat, reponse.url);
});

document.getElementById("remplir").addEventListener("click", () => {
  const bouton = document.getElementById("remplir");
  bouton.disabled = true;
  chrome.runtime.sendMessage({ type: "popupFill" }, (reponse) => {
    document.getElementById("message").textContent = reponse ? reponse.message : "Pas de réponse.";
    bouton.disabled = false;
  });
});
