import os
# Génère les pages de laboratoire (inoffensives) du spécimen 10 dans pages/
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
os.makedirs(OUT, exist_ok=True)

STYLE = """body{margin:0;font:16px/1.5 'Segoe UI',Arial,sans-serif;background:#f3f4f7;color:#1d2433}
main{max-width:440px;margin:60px auto;background:#fff;border-radius:12px;padding:32px 36px;box-shadow:0 6px 24px rgba(0,0,0,.08)}
h1{font-size:30px;margin:0 0 6px;color:%(couleur)s}h2{font-size:19px;margin:0 0 18px;font-weight:600}
p{margin:0 0 16px;color:#4a5164}label{display:block;font-size:14px;margin:12px 0 4px;color:#4a5164}
input{width:100%%;box-sizing:border-box;padding:10px 12px;border:1px solid #c9cfdb;border-radius:8px;font:inherit}
button{margin-top:20px;width:100%%;padding:12px;border:0;border-radius:8px;background:%(couleur)s;color:#fff;font:600 16px 'Segoe UI',Arial}
footer{max-width:440px;margin:12px auto;font-size:11px;color:#9aa1b0;text-align:center}"""

PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>%(titre)s</title><style>%(style)s</style></head>
<body><main>
<h1>%(marque)s</h1><h2>%(accroche)s</h2><p>%(texte)s</p>
<form onsubmit="return false" autocomplete="off">
<label>%(champ1)s</label><input type="text" name="identifiant">
<label>%(champ2)s</label><input type="password" name="secret">
<button type="submit">%(bouton)s</button>
</form></main>
<footer>Page de laboratoire CoreGuard (démo inoffensive) : le formulaire n'envoie rien.</footer>
</body></html>
"""

pages = {
    "paypal.html": dict(titre="Connexion", marque="PayPal", couleur="#1d4f91", accroche="Connectez-vous à votre compte",
        texte="Pour des raisons de sécurité, confirmez votre identité.", champ1="Adresse e-mail", champ2="Mot de passe", bouton="Connexion"),
    "ameli.html": dict(titre="Remboursement", marque="ameli", couleur="#0c6ab0", accroche="L'Assurance Maladie",
        texte="Vous avez un remboursement de 148,20 € en attente. Connectez-vous pour le recevoir.",
        champ1="Numéro de sécurité sociale", champ2="Mot de passe", bouton="Recevoir mon remboursement"),
    "orange-money.html": dict(titre="Orange Money", marque="Orange Money", couleur="#d35400", accroche="Recevez 25 000 FCFA",
        texte="Confirmez votre code secret Orange Money pour valider le transfert.", champ1="Numéro de téléphone",
        champ2="Code secret", bouton="Valider"),
    "mtn-momo.html": dict(titre="MTN MoMo", marque="MTN MoMo", couleur="#a07800", accroche="Votre compte MTN Mobile Money est suspendu",
        texte="Réactivez votre compte en confirmant votre code PIN.", champ1="Numéro MoMo", champ2="Code PIN", bouton="Réactiver"),
    "impots.html": dict(titre="impots.gouv.fr", marque="impots.gouv.fr", couleur="#000091",
        accroche="Direction générale des Finances publiques",
        texte="Un remboursement d'impôt de 312,00 € vous attend. Identifiez-vous pour le percevoir.",
        champ1="Numéro fiscal", champ2="Mot de passe", bouton="Se connecter"),
    "netflix.html": dict(titre="Netflix", marque="Netflix", couleur="#b20710", accroche="Votre paiement a échoué",
        texte="Mettez à jour vos informations pour éviter la suspension de votre abonnement.", champ1="E-mail",
        champ2="Mot de passe", bouton="Se connecter"),
    "club.html": dict(titre="Espace membres", marque="Club de tennis des Lilas", couleur="#2e7d32", accroche="Espace membres",
        texte="Réservez vos terrains et consultez le planning des cours.", champ1="Identifiant", champ2="Mot de passe",
        bouton="Entrer"),
    "boutique.html": dict(titre="Mon compte", marque="Atelier Céramique Martin", couleur="#6d4c41", accroche="Mon compte client",
        texte="Suivez vos commandes de poteries artisanales.", champ1="E-mail", champ2="Mot de passe", bouton="Connexion"),
    "colis.html": dict(titre="Suivi de colis", marque="Suivi de votre colis", couleur="#c27c0e",
        accroche="Votre colis est bloqué au centre de tri",
        texte="Des frais de réexpédition de 1,99 € sont nécessaires. Sans paiement sous 24 h, le colis sera renvoyé à l'expéditeur.",
        champ1="Numéro de carte bancaire", champ2="Cryptogramme (CVV)", bouton="Payer 1,99 €"),
    "crypto.html": dict(titre="Portefeuille", marque="Doublez vos bitcoins", couleur="#7b3fe4",
        accroche="Offre exclusive : 2 BTC offerts pour 1 BTC déposé",
        texte="Connectez votre portefeuille en saisissant votre phrase de récupération (12 mots) pour recevoir le bonus.",
        champ1="Adresse du portefeuille", champ2="Phrase de récupération", bouton="Recevoir le bonus"),
    "association.html": dict(titre="Adhérents", marque="Association des parents d'élèves", couleur="#00796b",
        accroche="Espace adhérents", texte="Consultez les comptes rendus des réunions et l'agenda de l'école.",
        champ1="Identifiant", champ2="Mot de passe", bouton="Se connecter"),
}

for name, d in pages.items():
    d = dict(d)
    d["style"] = STYLE % {"couleur": d["couleur"]}
    open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n").write(PAGE % d)
print(len(pages), "pages")
