# Audit CoreGuard — alignement sur l'architecture consolidée

*Audit du 24/11/2026 (commit `c0e9def`), mis à jour le 26/11/2026 après les étapes 1 à 5 du plan. Toutes les affirmations ci-dessous viennent d'une lecture du code et d'une exécution de `dotnet build` / `dotnet test`.*

## Synthèse

| Point | Constat |
|---|---|
| Compilation | `dotnet build AntivirusIA.slnx` : **0 erreur, 0 avertissement** (18 projets). |
| Tests | `dotnet test` : **306 tests verts** (84 socle + 57 Behavior + 38 Extension + 24 Privacy + 23 Ipc + 22 Service + 20 RealTime + 11 Vault + 10 Network + 10 Response + 7 AmsiProvider, ces derniers sur la DLL native réelle). |
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
| 2 | IA niveau 1 (EMBER / ONNX) | — | **Absent** | Pas de package `Microsoft.ML.OnnxRuntime`, pas de modèle, pas d'extraction de features EMBER. Le README l'annonçait à tort. |
| 3 | IA niveau 2 (LLM explication) | `AntivirusIA.AI/*` | **Complet** | LLamaSharp + Llama 3.2 3B GGUF, repli local si modèle absent, ne décide jamais. Désobfuscation de scripts non câblée (prompt d'explication seulement). |
| 4 | AMSI | `CoreGuard.AmsiProvider/*`, `CoreGuard.Service/ScriptScanner.cs` | **Complet (à valider installé)** | **Fournisseur AMSI** natif (NativeAOT, serveur COM `IAntimalwareProvider`) chargé par amsi.dll dans PowerShell, wscript/cscript, Office… : il transmet chaque contenu au service (pipe, 150 ms), qui applique les règles au texte et au Base64 décodé et répond « bloquer » (score ≥ 60 ou preuve forte). Fail-open si le service est absent. Testé sur la DLL native réelle (spécimen 01 bloqué de bout en bout). Restes : pas de version 32 bits, signature Authenticode non faite (Windows peut ignorer un fournisseur non signé), pas d'explication par le LLM dans le service. |
| 5 | ETW comportemental | `EtwProcessMonitor.cs`, `BehaviorRuleEngine.cs` | **Partiel** | Règles Office→shell (+ Base64), `vssadmin`/`wmic`/`diskshadow`/WMI, persistance par ligne de commande : OK et testées. La suppression des clichés est **arrêtée par `TerminateProcess`** (PID exact fourni par ETW) ; les autres règles alertent seulement. Exige l'admin ; l'arrêt suit le démarrage (une commande très rapide peut avoir agi avant). |
| 6 | Pare-feu WFP | `CoreGuard.Network/WindowsFirewall.cs` | **Partiel** | Passe par le **pare-feu COM** (`INetFwPolicy2`, règles par chemin), **pas par WFP** (`FwpmFilterAdd0`). Pas de blocage par PID. Kill switch implémenté mais non exposé dans l'UI. |
| 7 | Quarantaine chiffrée | `AntivirusIA.Infrastructure/QuarantineService.cs` | **Partiel** | AES-256-GCM authentifié + clé DPAPI + **droits NTFS restreints** sur chaque `.quar` (héritage coupé, exécution refusée à tous). Dossier sous `%LocalAppData%` (accessible au même utilisateur tant que le service n'existe pas). |
| 8 | Anti-ransomware canaris | `CoreGuard.RealTime/CanaryManager.cs`, `CanaryAudit.cs`, `CoreGuard.Service/CanaryGuard.cs`, `UserProfiles.cs` | **Complet (user-mode)** | Le service dépose des canaris **cachés** (noms de la spec) dans Documents, Bureau et Images de chaque profil, les restaure depuis une copie AES en mémoire (avec tentatives si le fichier est verrouillé), recrée la surveillance si le tampon déborde, et **arrête le processus coupable** identifié avec certitude par l'**audit NTFS** (SACL + événement 4663 : PID exact). Sans audit : alerte et restauration seules, jamais d'arrêt sur supposition. Essai réel en console (non admin) : 15/15 leurres attaqués par le spécimen 02 détectés et restaurés ; l'arrêt par audit reste à vérifier avec le service installé. |
| 9 | Scan mémoire (fileless) | — | **Absent** | Aucun `VirtualQueryEx` / `ReadProcessMemory`. |
| 10 | Moniteur BadUSB | — | **Absent** | Aucun `Win32_DeviceChangeEvent`, aucune analyse de cadence. Le spécimen `04-badusb-hid` existe mais rien ne le détecte. |
| 11 | Auto-défense (watchdog, ACL, HMAC) | `CoreGuard.Service/Watchdog.cs`, `ServiceHost.cs`, `CoreGuard.Ipc/StopAuthentication.cs` | **Complet (user-mode)** | DACL durcie du service et du watchdog (taskkill/Stop-Process : accès refusé, vérifié) ; watchdog mutuel (chacun relance l'autre, vérifié) ; `sc stop` refusé (`CanStop = false`) ; arrêt uniquement par mot de passe (défi-réponse HMAC, nonce unique, verrouillage après 5 échecs) qui prévient le watchdog par un signal HMAC. Limite : un administrateur avec SeDebugPrivilege peut encore tuer les deux processus simultanément (le gestionnaire de services relance alors le service). |
| 12 | Vault | `CoreGuard.Vault/Vault.cs` | **Partiel** | Argon2id + AES-256-GCM + SQLite : solide et testé. **Pas d'ACL NTFS**, **pas branché à l'UI**, l'hôte Native Messaging utilise `NullCredentialProvider` (l'auto-fill ne renvoie jamais rien). |
| 13 | Anti-infostealer navigateur | — | **Absent** | Ni ACL sur `Login Data` / `Local State` / `Cookies`, ni audit des lectures. Seule la règle de contenu `Stealer-BrowserCredentials` (statique) existe. |
| 14 | Anti-phishing visuel | `CoreGuard.Extension/*` | **Partiel** | Levenshtein, homographes, OCR Windows, QR (ZXing) : OK et testés. L'hôte n'est **pas enregistré** automatiquement (manifeste + clé de registre à créer, voir `INSTALL.txt`) et les verdicts ne remontent pas dans l'UI. |
| 15 | Presse-papiers intelligent | `CoreGuard.Privacy/ClipboardGuardian.cs` | **Complet** | `AddClipboardFormatListener`, restauration anti-clipper, vidage des secrets à 30 s. |
| 16 | Privacy Guard | `CoreGuard.Privacy/SensorMonitor.cs` | **Partiel** | Lecture du `ConsentStore` par scrutation : OK. **Pas de bouton de coupure** (ni kill du processus, ni désactivation du périphérique). |
| 17 | Mode Paranoïa | `CoreGuard.Privacy/ParanoiaMode.cs` | **Squelette** | Interrupteur et politique uniquement : **aucune action réelle** (ni USB, ni pare-feu liste blanche, ni blocage d'exécution). |
| 18 | Gardien de persistance | `CoreGuard.Behavior/PersistenceWatcher.cs` | **Partiel** | Scrutation Run/RunOnce + tâches planifiées + événement 7045 : OK. Dossier `Startup` non surveillé, **pas de pop-up Autoriser/Bloquer**, pas de retrait. |
| 19 | Smart Download Guard | `AntivirusIA.UI/Services/ProtectionService.cs` | **Partiel** | Scan automatique des nouveaux fichiers de Téléchargements (non récursif) avec signature Authenticode et règles. **`Zone.Identifier` non lu**, pas de score Vert/Orange/Rouge dédié, pas de score EMBER (cf. #2). |

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
| `CoreGuard.Vault` | Vault, IVault, VaultOptions | Complet côté crypto, non intégré |
| `CoreGuard.Privacy` | ClipboardGuardian, ClipboardAnalysis, SensorMonitor, ParanoiaMode | Partiel (Paranoïa = squelette) |
| `CoreGuard.Extension` | Program (hôte), HostRouter, NativeMessagingProtocol, OcrPhishingAnalyzer, PhishingLogic, QrCodeScanner, `extension/` (MV3) | Partiel (enregistrement de l'hôte et coffre non branchés) |
| `AntivirusIA.UI` | App (composition root DI), 5 vues, ViewModels, Services (Scan, Protection, AlertHub, Settings, Theme…) | Partiel : fonctionnel ; refonte visuelle en cours |
| `CoreGuard.Response` | UserModeActionProvider (arrêt, suspension, blocage réseau, ACL NTFS, DACL de processus), Native | Complet pour l'étape 1 |
| `CoreGuard.Ipc` | IpcContract (trames, messages), PipeServer (ACL, diffusion), ServiceClient (vérification session 0), StopAuthentication (PBKDF2 + HMAC) | Complet (état, alertes, arrêt authentifié) |
| `CoreGuard.Service` | Program (hôte + CLI), ProtectionWorker (ETW, arrêt VSS, pipe, arrêt authentifié, AMSI), Watchdog, ServiceHost, CanaryGuard, UserProfiles, ScriptScanner | Partiel : persistance HKLM et réseau restent à migrer |
| `CoreGuard.AmsiProvider` | ComServer (DllGetClassObject, fabrique, IAntimalwareProvider), ScanClient (pipe, contrôle session 0, fail-open) | Complet (x64, non signé) |
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
| `Microsoft.ML.OnnxRuntime` | ❌ | À ajouter avec le modèle EMBER |
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
| 4 | BadUSB HID | ✅ `04` | ❌ | ❌ | Moniteur HID + cadence |
| 5 | Injection mémoire | ❌ | ❌ | ❌ | Scanner mémoire + spécimen bénin (auto-injection dans un processus de test) |
| 6 | Phishing OCR | ✅ `06` | ✅ via l'extension, si l'hôte est enregistré | n/a (alerte) | Script d'installation de l'hôte, remontée UI |
| 7 | Anti-Infostealer | ✅ `07` | ❌ (aucun audit d'accès) | ❌ | ACL + audit SACL/ETW fichier |
| 8 | Crypto-Clipper | ✅ `05` | ✅ | ✅ restauration | — (démontrable) |
| 9 | Persistance | ✅ `03` | ✅ (≤ 5 s) | ❌ | Pop-up Autoriser/Bloquer + retrait |
| 10 | Privacy Guard caméra | ❌ | ✅ si une appli ouvre la caméra | ❌ | Bouton de coupure |

**Démontrables tels quels : 8 (clipper), 9 (détection), 6 (avec installation manuelle de l'hôte), 10 (détection).**

## 6. Plan d'implémentation ordonné

Chaque étape est livrable et testable seule ; l'ordre minimise les dépendances.

1. ✅ **`IKernelActionProvider` + `UserModeActionProvider`** (Core + `CoreGuard.Response`) : arrêt, suspension, blocage réseau, ACL fichier, DACL processus ; arrêt réel des suppressions de clichés détectées par ETW ; ACL NTFS sur la quarantaine. *Fait le 25/11/2026.*
2. ✅ **`CoreGuard.Service`** (Worker Service, LocalSystem) + **`CoreGuard.Ipc`** : ETW et arrêt des suppressions de clichés tournent dans le service ; pipe local avec ACL (réseau refusé, utilisateurs interactifs en lecture/écriture), canal v1 en lecture seule (état + alertes, aucune commande), client qui rejette tout serveur hors session 0 (anti-usurpation) ; repli automatique sur l'ETW local. Installation : `scripts/install-service.ps1`. *Fait le 25/11/2026 ; reste à migrer persistance HKLM, réseau et canaris côté service.*
3. ✅ **Auto-défense** : watchdog mutuel, DACL durcie, `sc stop` refusé, arrêt par mot de passe (défi-réponse HMAC depuis l'UI ou `CoreGuard.Service.exe --stop`), signal HMAC au watchdog ; mot de passe défini à l'installation (`--set-password`, administrateur). Spécimen `demo/08-anti-kill`. *Fait le 26/11/2026.*
4. ✅ **Réponse ransomware** : canaris gérés par le service (cachés, noms de la spec, tous les profils), attribution par audit NTFS et arrêt du PID exact, restauration robuste, `FileSystemWatcher.Error` géré, spécimen 02 corrigé (vise les leurres, liste blanche stricte, se relance dans un processus dédié). *Fait le 26/11/2026.*
5. ✅ **Fournisseur AMSI** : DLL NativeAOT `CoreGuard.AmsiProvider` (COM in-process, enregistrée sous `HKLM\SOFTWARE\Microsoft\AMSI\Providers` par `install-service.ps1`), analyse côté service (`ScriptScanner` : règles + désobfuscation Base64), alerte dans l'UI. *Fait le 26/11/2026.*
6. **Moniteur BadUSB** : `ManagementEventWatcher` sur `Win32_DeviceChangeEvent` + hook clavier bas niveau pendant N s après branchement (cadence > 500 car/s, variance ≈ 0) → blocage des entrées (`BlockInput`) et alerte. *Scénario 4.*
7. **Scanner mémoire** : `VirtualQueryEx` sur les processus utilisateur, régions `MEM_PRIVATE` + `PAGE_EXECUTE_READWRITE` (ou exécutables non adossées à une image), en-tête MZ en mémoire → kill + alerte ; spécimen bénin qui alloue une région RWX dans **son propre** processus. *Scénario 5.*
8. **Anti-infostealer** : ACL sur les fichiers des profils Chrome/Edge/Brave (accès réservé au navigateur via le service), SACL d'audit + lecture des événements 4663, ou ETW `Microsoft-Windows-Kernel-File` ; alerte sur tout processus non-navigateur. *Scénario 7.*
9. **Privacy Guard actif** : bouton « Couper » (kill du processus ou désactivation du périphérique via SetupAPI) + badge. Spécimen : ouverture de la caméra par un petit outil de test. *Scénario 10.*
10. **Persistance interactive** : pop-up Autoriser/Bloquer, retrait de la valeur Run / de la tâche, dossier Startup, explication LLM en une ligne. *Scénario 9.*
11. **Extension** : script d'enregistrement de l'hôte Native Messaging, branchement du Vault (`ICredentialProvider`), remontée des verdicts dans l'UI. *Scénario 6.*
12. **IA niveau 1** : extraction de features EMBER (sous-ensemble), modèle ONNX entraîné hors ligne, `OnnxRuntime`, budget < 50 ms ; **WFP natif** (`FwpmFilterAdd0` par AppId) ; **Mode Paranoïa réel** ; **Zone.Identifier** dans le Download Guard.

Les étapes 1 à 4 sont le chemin critique : sans service ni réponse réelle, aucune démo ne montre un **blocage**.
