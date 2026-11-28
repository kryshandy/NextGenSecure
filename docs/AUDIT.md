# Audit CoreGuard — alignement sur l'architecture consolidée

*Audit du 24/11/2026 (commit `c0e9def`), mis à jour le 27/11/2026 après les étapes 1 à 9 du plan. Toutes les affirmations ci-dessous viennent d'une lecture du code et d'une exécution de `dotnet build` / `dotnet test`.*

## Synthèse

| Point | Constat |
|---|---|
| Compilation | `dotnet build AntivirusIA.slnx` : **0 erreur, 0 avertissement** (18 projets). |
| Tests | `dotnet test` : **461 tests verts** (89 socle et IA niveau 1 + 77 Behavior + 75 Extension + 53 Ipc + 39 Service + 30 RealTime + 28 Privacy + 18 Devices + 13 Memory + 11 Network + 11 Vault + 10 Response + 7 AmsiProvider) ; 1 test ignoré hors administrateur (blocage WFP réel), réussi en console administrateur. |
| Ring 0 | Aucun code ne référence de driver : rien ne bloque sans `CoreGuard.Driver`. L'abstraction **`IKernelActionProvider`** (Core) est en place, avec **`UserModeActionProvider`** (CoreGuard.Response) câblé par défaut. |
| Composants | Les 3 composants existent. **`CoreGuard.Service`** (Worker Service LocalSystem, session 0) héberge la télémétrie ETW et la réponse associée ; l'UI s'y connecte par named pipe et garde les modules liés à la session (presse-papiers, caméra/micro, canaris, téléchargements, persistance HKCU). Sans service, l'UI reprend ETW elle-même. |
| Framework | Le code cible **.NET 10** (LTS), pas .NET 8/9. Aucune raison de redescendre : .NET 10 est la LTS actuelle et toutes les dépendances le supportent. |
| Démos | 7 spécimens sur 10. **Aucun des 10 scénarios n'est démontrable de bout en bout aujourd'hui avec blocage réel** (voir §5). |

Légende des états : **Complet** (fait ce que la spec demande) · **Partiel** (fonctionne, mais une partie de la spec manque) · **Squelette** (contrat ou intention, pas de comportement réel) · **Absent** · **Bug** (comportement incorrect).

---

## 1. État par fonctionnalité (inventaire de la spec)

| # | Fonctionnalité | Fichiers | État | Écart par rapport à la spec |
|---|---|---|---|---|
| 1 | Scan statique PE | `AntivirusIA.Engines/PeStaticEngine.cs` | **Complet** | Entropie par section, RWX, déséquilibre virtuel/brut, IAT pondérée, PE malformé = suspect. |
| — | Signatures, règles de contenu, Authenticode | `SignatureEngine.cs`, `PatternRuleEngine.cs`, `Data/rules.json`, `AuthenticodeVerifier.cs` | **Complet** | Base de signatures livrée minimale (EICAR) : à alimenter avec un flux public (format `.txt` supporté). |
| 2 | IA niveau 1 (EMBER / ONNX) | `AntivirusIA.Ml/EmberFeatures.cs`, `EmberOnnxEngine.cs`, `Models/ember-subset.onnx`, `scripts/ml/train_ember_subset.py` | **Complet** | Sous-ensemble EMBER calculable sur les octets (616 caractéristiques : histogramme, histogramme d'entropie, chaînes), identique à la référence (test de parité). LightGBM entraîné sur 199 541 fichiers EMBER 2018, exporté en ONNX, ONNX Runtime en C#. Test EMBER (100 561 fichiers) : AUC 0,980 ; seuil bas 84,1 % détectés / 1,92 % de fausses alertes ; seuil haut 62,7 % / 0,23 %. System32 (2 177 fichiers sains) : 0 alerte au seuil haut. ≈ 17 ms par fichier (budget 50 ms). Indice heuristique (+20 / +40 points), atténué si le fichier est signé. |
| 3 | IA niveau 2 (LLM explication) | `AntivirusIA.AI/*` | **Complet** | LLamaSharp + Llama 3.2 3B GGUF, repli local si modèle absent, ne décide jamais. Désobfuscation de scripts non câblée (prompt d'explication seulement). |
| 4 | AMSI | `CoreGuard.AmsiProvider/*`, `CoreGuard.Service/ScriptScanner.cs` | **Complet (à valider installé)** | **Fournisseur AMSI** natif (NativeAOT, serveur COM `IAntimalwareProvider`) chargé par amsi.dll dans PowerShell, wscript/cscript, Office… : il transmet chaque contenu au service (pipe, 150 ms), qui applique les règles au texte et au Base64 décodé et répond « bloquer » (score ≥ 60 ou preuve forte). Fail-open si le service est absent. Testé sur la DLL native réelle (spécimen 01 bloqué de bout en bout). Restes : pas de version 32 bits, signature Authenticode non faite (Windows peut ignorer un fournisseur non signé), pas d'explication par le LLM dans le service. |
| 5 | ETW comportemental | `EtwProcessMonitor.cs`, `BehaviorRuleEngine.cs` | **Partiel** | Règles Office→shell (+ Base64), `vssadmin`/`wmic`/`diskshadow`/WMI, persistance par ligne de commande : OK et testées. La suppression des clichés est **arrêtée par `TerminateProcess`** (PID exact fourni par ETW) ; les autres règles alertent seulement. Exige l'admin ; l'arrêt suit le démarrage (une commande très rapide peut avoir agi avant). |
| 6 | Pare-feu WFP | `CoreGuard.Network/WfpFirewall.cs`, `WindowsFirewall.cs` | **Complet** | **WFP natif** (`fwpuclnt.dll` : `FwpmEngineOpen0`, sous-couche CoreGuard, `FwpmFilterAdd0` par AppId `FwpmGetAppIdFromFileName0`, couches ALE connect / recv-accept v4 et v6). Session dynamique (filtres retirés par Windows à la fermeture) ou persistante. Utilisé par le service pour isoler un programme malveillant (repli pare-feu COM sans droits) et par le Mode Paranoïa. Vérifié en console administrateur : curl bloqué par AppId puis débloqué. WFP ne propose pas de condition par PID : blocage par exécutable. |
| 7 | Quarantaine chiffrée | `AntivirusIA.Infrastructure/QuarantineService.cs` | **Partiel** | AES-256-GCM authentifié + clé DPAPI + **droits NTFS restreints** sur chaque `.quar` (héritage coupé, exécution refusée à tous). Dossier sous `%LocalAppData%` (accessible au même utilisateur tant que le service n'existe pas). |
| 8 | Anti-ransomware canaris | `CoreGuard.RealTime/CanaryManager.cs`, `CanaryAudit.cs`, `CoreGuard.Service/CanaryGuard.cs`, `UserProfiles.cs` | **Complet (user-mode)** | Le service dépose des canaris **cachés** (noms de la spec) dans Documents, Bureau et Images de chaque profil, les restaure depuis une copie AES en mémoire (avec tentatives si le fichier est verrouillé), recrée la surveillance si le tampon déborde, et **arrête le processus coupable** identifié avec certitude par l'**audit NTFS** (SACL + événement 4663 : PID exact). Sans audit : alerte et restauration seules, jamais d'arrêt sur supposition. Essai réel en console (non admin) : 15/15 leurres attaqués par le spécimen 02 détectés et restaurés ; l'arrêt par audit reste à vérifier avec le service installé. |
| 9 | Scan mémoire (fileless) | `CoreGuard.Memory/*`, `CoreGuard.Service/MemoryGuard.cs` | **Complet (user-mode)** | Scan de tous les processus accessibles toutes les 30 s par le service : `VirtualQueryEx` + `ReadProcessMemory` sur les régions privées exécutables. **Image PE (MZ + « PE\0\0 ») en mémoire privée → arrêt du processus hôte.** Les régions RWX sans PE sont seulement comptées : un scan à blanc d'un poste réel en a trouvé chez ~17 programmes légitimes (MSBuild, WhatsApp, Explorer…), et aucun faux positif PE sur 265 processus. Essai réel : spécimen 09 arrêté ~30 s après son lancement. Limite : on arrête l'hôte du code injecté, pas forcément l'injecteur. |
| 10 | Moniteur BadUSB | `CoreGuard.Devices/*` | **Complet** | Hook clavier bas niveau (WH_KEYBOARD_LL) dans la session de l'utilisateur : analyse de cadence sur 30 frappes (débit > 200 car/s, ou ≥ 40 car/s avec coefficient de variation < 0,3), répétitions de touche ignorées ; à la détection, toutes les frappes sont avalées 10 s (prolongé tant que l'injection continue). Nouveau clavier branché (GetRawInputDeviceList) : alerte + vigilance 60 s (seuil abaissé à 25 car/s). Essai réel : spécimen 04 détecté et bloqué. Limite : la saisie automatique d'un gestionnaire de mots de passe peut être bloquée (module désactivable). |
| 11 | Auto-défense (watchdog, ACL, HMAC) | `CoreGuard.Service/Watchdog.cs`, `ServiceHost.cs`, `CoreGuard.Ipc/StopAuthentication.cs` | **Complet (user-mode)** | DACL durcie du service et du watchdog (taskkill/Stop-Process : accès refusé, vérifié) ; watchdog mutuel (chacun relance l'autre, vérifié) ; `sc stop` refusé (`CanStop = false`) ; arrêt uniquement par mot de passe (défi-réponse HMAC, nonce unique, verrouillage après 5 échecs) qui prévient le watchdog par un signal HMAC. Limite : un administrateur avec SeDebugPrivilege peut encore tuer les deux processus simultanément (le gestionnaire de services relance alors le service). |
| 12 | Vault | `CoreGuard.Vault/Vault.cs`, `AntivirusIA.UI/Services/VaultService.cs`, page Coffre-fort, `CoreGuard.Ipc/VaultBroker.cs` | **Complet** | Argon2id + AES-256-GCM + SQLite ; page « Coffre-fort » (création, déverrouillage, ajout avec générateur, suppression), verrouillage automatique après 15 min, ACL du fichier réservée à l'utilisateur et à SYSTEM. Auto-remplissage : pipe propre à l'utilisateur ; l'interface n'y répond qu'à l'hôte CoreGuard lancé par un navigateur signé (vérification d'ascendance + Authenticode), uniquement pour l'hôte exact de la page et en https. Essai réel : hôte lancé hors navigateur → refusé. |
| 13 | Anti-infostealer navigateur | `CoreGuard.Service/CredentialGuard.cs`, `CredentialTargets.cs`, `CredentialAccessPolicy.cs` | **Complet (user-mode)** | Audit NTFS **en lecture** (SACL ReadData + événement 4663 = PID exact) sur `Login Data`, `Local State`, `Cookies`, `Web Data` (Chrome, Edge, Brave) et `logins.json`, `key4.db`, `cookies.sqlite` (Firefox) de chaque profil, réappliqué toutes les 2 min. Lecteur autorisé : navigateur reconnu par nom **et** signature Authenticode de l'éditeur attendu, Defender et l'indexation depuis les dossiers système ; tout autre lecteur (programme inconnu, PowerShell, `cmd /c copy`…) est **arrêté**. **Profil leurre Chromium** (créé seulement si Chromium n'est pas installé) : tout lecteur est arrêté. Pas d'ACL préventive : navigateur et voleur tournent sous le même compte, une ACL ne peut pas les distinguer ; la lecture a lieu avant l'arrêt (conseil de changer les mots de passe). Essai réel en console : 28 fichiers inventoriés, leurre créé et retiré ; arrêt à vérifier avec le service installé. |
| 14 | Anti-phishing visuel | `CoreGuard.Extension/*` (TrustBase, PublicSuffixList, SiteAnalyzer, HostRouter), `CoreGuard.Ipc/SiteReview.cs`, `AntivirusIA.UI/Services/PhishingReviewService.cs`, `scripts/install-browser-extension.ps1` | **Complet** | Extension 0.3.0 (ID fixe). **Base de confiance locale** : 100 000 domaines Tranco, Public Suffix List (domaine enregistrable exact, hébergeurs partagés jamais « connus »), liste noire OpenPhish livrée + personnelle + mise à jour optionnelle (désactivée par défaut). **Cascade** : confiance utilisateur → liste noire → domaine connu (sans capture) → règles d'URL → OCR + QR si mot de passe sur un site non connu → **revue par l'IA locale** (zone grise, JSON, ne peut qu'aggraver). **Affichage** : page d'interception « CoreGuard n'aime pas ce site », fenêtre « CoreGuard doute de ce site » dans la page (clics `isTrusted` seulement), avis de l'IA ; « Je fais confiance » confirmé dans la fenêtre CoreGuard. Verdicts relayés dans le tableau de bord (bulle Windows si cachée). IA bornée par un garde-fou « indice objectif » (marque usurpée ou données sensibles). Mesure `demo/10-phishing-ia` (19 cas) : règles seules 9/11 arnaques, 0 fausse alerte ; règles + IA 11/11, 0 fausse alerte. Vérifié en direct dans Edge (profil temporaire). |
| 15 | Presse-papiers intelligent | `CoreGuard.Privacy/ClipboardGuardian.cs` | **Complet** | `AddClipboardFormatListener`, restauration anti-clipper, vidage des secrets à 30 s. |
| 16 | Privacy Guard | `CoreGuard.Privacy/SensorMonitor.cs`, `SensorControl.cs`, tableau de bord | **Complet** | Détection par le `ConsentStore` + carte « Caméra / micro en cours d'utilisation » avec bouton **Couper** : arrêt des processus de l'application (retrouvés par chemin exact d'exécutable) et, pour une app du Store, refus d'accès par application. Pour les applications de bureau, Windows n'a qu'un interrupteur global : Réglages > « Interdire la caméra / le micro aux applications de bureau ». |
| 17 | Mode Paranoïa | `CoreGuard.Service/ParanoiaGuard.cs`, `CoreGuard.Behavior/UserDirExecutionGuard.cs`, `CoreGuard.Privacy/ParanoiaMode.cs` | **Complet** | Service : USBSTOR désactivé, WFP dynamique (entrées refusées hors loopback, LOLBins coupés d'Internet), exécutable non signé lancé depuis un dossier utilisateur arrêté dès son démarrage (ETW), état persistant (ré-appliqué au redémarrage), désactivation par mot de passe de protection (défi-réponse HMAC). Sans service : blocage d'exécution par scrutation (sans admin), vérifié en réel (`demo/12-paranoia`). |
| 18 | Gardien de persistance | `CoreGuard.Behavior/PersistenceWatcher.cs`, `PersistenceRisk.cs`, `ScheduledTasks.cs`, `AntivirusIA.UI/Services/PersistencePromptService.cs`, `PersistencePromptWindow` | **Complet (utilisateur)** | Run/RunOnce, tâches planifiées (COM Planificateur, sans admin), dossiers Démarrage, services 7045. Fenêtre **Autoriser / Bloquer** avec niveau de risque et raisons (règles), explication en une phrase par le LLM local si activé. **Bloquer** supprime la valeur Run / la tâche, met le fichier Démarrage **en quarantaine** (restaurable) ; entrées HKLM/services : admin requis (échec propre). Choix « Autoriser » mémorisé par empreinte (entrée + commande). Vérifié en réel avec le spécimen 03. |
| 19 | Smart Download Guard | `CoreGuard.RealTime/MarkOfTheWeb.cs`, `AntivirusIA.UI/Views/DownloadGuardWindow`, `ProtectionService.cs` | **Complet** | Lecture du flux NTFS `Zone.Identifier` (zone, HostUrl, ReferrerUrl), verdict vert / orange / rouge combinant origine, type, signature Authenticode et moteurs (dont l'IA niveau 1), fenêtre empilable avec quarantaine en un clic. Vérifié en réel (`demo/11-telechargement`). |
| + | Verrouillage d'urgence (ajout) | `CoreGuard.Service/Lockdown.cs`, `RemoteLock.cs`, `CoreGuard.Devices/InputLockHook.cs`, `AntivirusIA.UI/Services/LockdownController.cs`, `LockScreenWindow` | **Complet (user-mode, écran non vérifié visuellement)** | Déclencheurs : bouton « Verrouiller le PC », BadUSB détecté (option), **ordre à distance par dossier synchronisé** (opt-in : `--set-remote-lock`, fichier-ordre contenant le code, empreinte PBKDF2, fichier renommé pour ne pas être rejoué). Effets : session Windows verrouillée, écran CoreGuard plein écran sur tous les moniteurs, raccourcis système bloqués (touche Windows, Alt+Tab, Alt+F4, Ctrl+Échap) et toute frappe hors de l'écran, processus de l'UI durci, stockage USB désactivé, nouveaux périphériques refusés (stratégie DeviceInstall), coupure réseau optionnelle ; état persistant ré-appliqué au redémarrage. Déverrouillage : **Ctrl+R** fait apparaître la saisie (écran neutre sinon), puis mot de passe de protection (défi-réponse HMAC, 5 essais puis 5 min) ; valeurs système d'origine restaurées exactement. Limites : Ctrl+Alt+Suppr reste accessible (Windows), la déconnexion de session ferme l'écran jusqu'au prochain lancement de l'UI (USB et réseau restent bloqués par le service). |
| + | Mode arrière-plan (ajout) | `AntivirusIA.UI/Services/BackgroundHost.cs`, `App.xaml.cs` | **Complet** | Icône de zone de notification avec menu, fermeture = masquage (`ShutdownMode=OnExplicitShutdown`), bulles d'alerte quand la fenêtre est cachée, démarrage caché à l'ouverture de session (HKCU Run `--background`, reconnu par le gardien de persistance), instance unique (mutex + événement nommé). Rend permanents les modules hébergés par l'application. Vérifié en réel. |

## 2. Inventaire par projet

| Projet | Fichiers | État |
|---|---|---|
| `AntivirusIA.Core` | `Interfaces/*` (IDetectionEngine, IAiProvider, IQuarantineService, IScanRepository, IFileTrustProvider), `Models/*`, `Services/ScanPipeline.cs`, `ScoringService.cs` | Complet |
| `AntivirusIA.Engines` | Signature, PatternRule, Heuristic, Entropy, PeStatic, Authenticode, FileHasher, FileTypes, `Data/` | Complet (base de signatures à alimenter) |
| `AntivirusIA.AI` | LLamaSharpProvider, AiPromptBuilder, AiResponseParser, AiOptions, DI | Complet pour le niveau 2 ; niveau 1 absent |
| `AntivirusIA.Infrastructure` | QuarantineService, SqliteScanRepository | Complet (hors ACL NTFS) |
| `CoreGuard.RealTime` | CanaryManager, CanaryAudit (SACL + 4663), RealtimeFileMonitor, PidResolver, IThreatResponder, CanaryAlert | Complet (attribution par audit ; PidResolver ne sert plus à arrêter) |
| `CoreGuard.Behavior` | EtwProcessMonitor, BehaviorRuleEngine, AmsiScanner, PersistenceWatcher, ProcessEvent, IProcessTelemetry | Partiel (détection sans blocage ; AMSI non intercepteur) |
| `CoreGuard.Network` | WindowsFirewall (COM), PortInspector, TcpTableParser, RuleNaming, Connection | Partiel (pas de WFP natif) |
| `CoreGuard.Vault` | Vault, IVault, VaultOptions | Complet, branché à l'UI et à l'extension |
| `CoreGuard.Privacy` | ClipboardGuardian, ClipboardAnalysis, SensorMonitor, ParanoiaMode | Partiel (Paranoïa = squelette) |
| `CoreGuard.Extension` | Program (hôte), HostRouter (checkUrl, analyzeCapture, reviewSite, trustSite, requestCredential), TrustBase, PublicSuffixList, SiteAnalyzer, NativeMessagingProtocol, OcrPhishingAnalyzer, PhishingLogic, QrCodeScanner, `Data/` (Tranco, PSL, OpenPhish), `extension/` (MV3 0.3.0 : background, content, popup, blocked) | Complet |
| `AntivirusIA.UI` | App (composition root DI), 5 vues, ViewModels, Services (Scan, Protection, AlertHub, Settings, Theme…) | Partiel : fonctionnel ; refonte visuelle en cours |
| `CoreGuard.Response` | UserModeActionProvider (arrêt, suspension, blocage réseau, ACL NTFS, DACL de processus), Native | Complet pour l'étape 1 |
| `CoreGuard.Ipc` | IpcContract (trames, messages), PipeServer (ACL, diffusion), ServiceClient (vérification session 0), StopAuthentication (PBKDF2 + HMAC) | Complet (état, alertes, arrêt authentifié) |
| `CoreGuard.Service` | Program (hôte + CLI), ProtectionWorker, Watchdog, ServiceHost, CanaryGuard, UserProfiles, ScriptScanner, MemoryGuard, CredentialGuard / CredentialTargets / CredentialAccessPolicy | Partiel : persistance HKLM et réseau restent à migrer |
| `CoreGuard.AmsiProvider` | ComServer (DllGetClassObject, fabrique, IAntimalwareProvider), ScanClient (pipe, contrôle session 0, fail-open) | Complet (x64, non signé) |
| `CoreGuard.Devices` | KeystrokeCadenceAnalyzer, KeyboardInjectionGuard (logique pure), BadUsbMonitor (hook WH_KEYBOARD_LL, claviers branchés) | Complet |
| `CoreGuard.Memory` | MemoryRegionClassifier (logique pure), ProcessMemoryScanner (VirtualQueryEx / ReadProcessMemory) | Complet |
| Tests (7 projets) | MSTest | Complet pour ce qui existe |

## 3. Découplage Ring 0

- **Aucune dépendance au driver** : aucun projet ne référence `CoreGuard.Driver`, aucun appel `FilterConnectCommunicationPort`, aucun `DeviceIoControl`. Rien ne bloque ni ne plante en son absence.
- **Abstraction en place (étape 1)** : `AntivirusIA.Core/Interfaces/IKernelActionProvider.cs`, implémentée par `CoreGuard.Response/UserModeActionProvider.cs` et enregistrée dans la composition root (`App.xaml.cs`). Les modules (quarantaine, réponse aux menaces) ne connaissent que l'interface. Garde-fous : refus des PID ≤ 4, de CoreGuard lui-même, des processus critiques de Windows (liste + `IsProcessCritical`). Contrat :

```csharp
public interface IKernelActionProvider
{
    bool IsKernelBacked { get; }                         // false en user-mode
    Task<ActionResult> TerminateProcessAsync(int pid, string reason, CancellationToken ct = default);
    Task<ActionResult> SuspendProcessAsync(int pid, CancellationToken ct = default);
    Task<ActionResult> ResumeProcessAsync(int pid, CancellationToken ct = default);
    Task<ActionResult> BlockNetworkAsync(int pid, string? imagePath, CancellationToken ct = default);
    Task<ActionResult> ProtectFileAsync(string path, CancellationToken ct = default);   // ACL NTFS
    Task<ActionResult> ProtectSelfAsync(CancellationToken ct = default);                 // DACL processus
}
```

  `UserModeActionProvider` s'appuie sur `TerminateProcess`, `NtSuspendProcess`/`NtResumeProcess`, le pare-feu (injecté), les ACL NTFS et `SetSecurityInfo` ; un futur `DriverActionProvider` se substitue dans la composition root sans toucher aux modules.

## 4. Dépendances NuGet

| Package demandé | Présent | Remarque |
|---|---|---|
| `Microsoft.Diagnostics.Tracing.TraceEvent` | ✅ 4.0.2 | CoreGuard.Behavior |
| `Microsoft.ML.OnnxRuntime` | ✅ 1.32 | Modèle EMBER (`AntivirusIA.Ml`) |
| `LLamaSharp` (+ `Backend.Cpu`) | ✅ 0.30.0 | AntivirusIA.AI |
| `System.Reflection.PortableExecutable` | ✅ intégré au runtime | Aucun package nécessaire sur .NET 10 |
| `ZXing.Net` | ✅ 0.16.10 | CoreGuard.Extension |
| `Konscious.Security.Cryptography.Argon2` | ✅ 1.3.1 | CoreGuard.Vault |
| `Meziantou.Framework.Win32.Amsi` | ❌ | Inutile : P/Invoke direct déjà en place |
| Autres | CommunityToolkit.Mvvm, Microsoft.Data.Sqlite, DI, EventLog, ProtectedData | OK |

## 5. Les 10 scénarios Red Team : état réel

| # | Scénario | Spécimen | Détecté aujourd'hui ? | Bloqué ? | Ce qui manque |
|---|---|---|---|---|---|
| 1 | PowerShell AMSI | ✅ `01` | ✅ (fournisseur AMSI) | ✅ script bloqué avant exécution | Vérifier avec le fournisseur enregistré (admin) |
| 2 | Ransomware VSS/Canari | ✅ `02` (corrigé) | ✅ leurres touchés détectés + restaurés ; VSS par ETW | ✅ arrêt du spécimen par audit NTFS (service installé) ; commande VSS arrêtée | Vérifier l'arrêt avec le service installé |
| 3 | Anti-Kill Watchdog | ✅ `08` | ✅ | ✅ arrêt refusé, relance mutuelle | Vérifier en service installé (essais faits en console) |
| 4 | BadUSB HID | ✅ `04` | ✅ cadence de frappe | ✅ frappes avalées 10 s | Lancer le spécimen de façon interactive (il n'injecte que si sa fenêtre a le focus) |
| 5 | Injection mémoire | ✅ `09` | ✅ image PE en mémoire privée | ✅ processus hôte arrêté (≤ 50 s) | Montrer l'alerte « Code injecté » dans l'UI |
| 6 | Phishing OCR | ✅ `06`, `10` | ✅ base de confiance + OCR + QR + IA locale | ✅ interception, « doute », remplissage refusé | mesure : `dotnet run --project demo/10-phishing-ia/eval` ; en direct : installer l'extension |
| 7 | Anti-Infostealer | ✅ `07` (corrigé) | ✅ lecture du leurre / des bases par un non-navigateur | ✅ voleur arrêté (service installé + audit) | Vérifier avec le service installé |
| 8 | Crypto-Clipper | ✅ `05` | ✅ | ✅ restauration | — (démontrable) |
| 9 | Persistance | ✅ `03` | ✅ (≤ 5 s) | ✅ Autoriser/Bloquer, retrait réel | — |
| 10 | Privacy Guard caméra | — (ouvrir l'appli Caméra ou une visio) | ✅ | ✅ bouton Couper | Démontrable sans spécimen |

**Démontrables tels quels : 8 (clipper), 9 (détection), 6 (avec installation manuelle de l'hôte), 10 (détection).**

## 6. Plan d'implémentation ordonné

Chaque étape est livrable et testable seule ; l'ordre minimise les dépendances.

1. ✅ **`IKernelActionProvider` + `UserModeActionProvider`** (Core + `CoreGuard.Response`) : arrêt, suspension, blocage réseau, ACL fichier, DACL processus ; arrêt réel des suppressions de clichés détectées par ETW ; ACL NTFS sur la quarantaine. *Fait le 25/11/2026.*
2. ✅ **`CoreGuard.Service`** (Worker Service, LocalSystem) + **`CoreGuard.Ipc`** : ETW et arrêt des suppressions de clichés tournent dans le service ; pipe local avec ACL (réseau refusé, utilisateurs interactifs en lecture/écriture), canal v1 en lecture seule (état + alertes, aucune commande), client qui rejette tout serveur hors session 0 (anti-usurpation) ; repli automatique sur l'ETW local. Installation : `scripts/install-service.ps1`. *Fait le 25/11/2026 ; reste à migrer persistance HKLM, réseau et canaris côté service.*
3. ✅ **Auto-défense** : watchdog mutuel, DACL durcie, `sc stop` refusé, arrêt par mot de passe (défi-réponse HMAC depuis l'UI ou `CoreGuard.Service.exe --stop`), signal HMAC au watchdog ; mot de passe défini à l'installation (`--set-password`, administrateur). Spécimen `demo/08-anti-kill`. *Fait le 26/11/2026.*
4. ✅ **Réponse ransomware** : canaris gérés par le service (cachés, noms de la spec, tous les profils), attribution par audit NTFS et arrêt du PID exact, restauration robuste, `FileSystemWatcher.Error` géré, spécimen 02 corrigé (vise les leurres, liste blanche stricte, se relance dans un processus dédié). *Fait le 26/11/2026.*
5. ✅ **Fournisseur AMSI** : DLL NativeAOT `CoreGuard.AmsiProvider` (COM in-process, enregistrée sous `HKLM\SOFTWARE\Microsoft\AMSI\Providers` par `install-service.ps1`), analyse côté service (`ScriptScanner` : règles + désobfuscation Base64), alerte dans l'UI. *Fait le 26/11/2026.*
6. ✅ **Moniteur BadUSB** : `CoreGuard.Devices` (analyse de cadence + blocage par le hook clavier, détection des nouveaux claviers), module « Clavier (BadUSB) » dans l'UI. *Fait le 26/11/2026.*
7. ✅ **Scanner mémoire** : `CoreGuard.Memory` (classement des régions, scan des processus) + `MemoryGuard` dans le service (scan toutes les 30 s, arrêt sur image PE en mémoire privée), spécimen `demo/09-injection-memoire`. *Fait le 26/11/2026.*
8. ✅ **Anti-infostealer** : audit en lecture des fichiers d'identifiants de tous les navigateurs et profils, politique « navigateur signé uniquement », profil leurre Chromium, arrêt du voleur ; spécimen 07 corrigé (ne lit que le leurre, après vérification du marqueur). *Fait le 26/11/2026.*
9. ✅ **Privacy Guard actif** : bouton « Couper » (arrêt de l'application + refus d'accès quand Windows le permet), interdiction globale caméra/micro aux applications de bureau dans Réglages. *Fait le 27/11/2026.*
10. ✅ **Persistance interactive** : pop-up Autoriser/Bloquer, retrait de la valeur Run / de la tâche, dossier Startup, explication LLM en une ligne. *Scénario 9.*
11. ✅ **Extension** : script d'installation de l'hôte (fait), coffre branché à l'auto-remplissage (fait), vérification des pages à la navigation et bandeau (fait) ; reste : relayer les verdicts de l'extension dans l'interface CoreGuard. *Mis à jour le 27/11/2026.*
12. ✅ **IA niveau 1** : extraction de features EMBER (sous-ensemble), modèle ONNX entraîné hors ligne, `OnnxRuntime`, budget < 50 ms ; **WFP natif** (`FwpmFilterAdd0` par AppId) ; **Mode Paranoïa réel** ; **Zone.Identifier** dans le Download Guard.

Les étapes 1 à 4 sont le chemin critique : sans service ni réponse réelle, aucune démo ne montre un **blocage**.
