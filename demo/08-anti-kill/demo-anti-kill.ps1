<#
DÉMO — INOFFENSIF : spécimen 08 (scénario « Anti-Kill / Watchdog »)

Imite ce que ferait un malware pour neutraliser l'antivirus avant d'agir : il tente d'arrêter le service
CoreGuard par les moyens habituels, puis affiche ce que CoreGuard a refusé. Il ne vise QUE CoreGuard.

Attendu (service installé via scripts/install-service.ps1) :
  - Stop-Service / sc stop : refusés (le service n'accepte pas l'arrêt par le gestionnaire de services) ;
  - taskkill /F du service et du watchdog : « Accès refusé » (DACL durcie) ;
  - si un administrateur parvient à tuer l'un des deux, l'autre le relance en quelques secondes.
Seul l'arrêt par mot de passe (Réglages > Désactiver, ou CoreGuard.Service.exe --stop) fonctionne.

Lancer : .\08-anti-kill\demo-anti-kill.ps1     Nettoyage : aucun.
#>
$serviceName = 'CoreGuardService'
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $svc) { Write-Output "Service $serviceName non installé : lancez d'abord scripts/install-service.ps1."; return }
Write-Output "État initial : $($svc.Status)"

Write-Output "`n1) Stop-Service"
try { Stop-Service -Name $serviceName -Force -ErrorAction Stop; Write-Output "   -> ARRÊTÉ (protection insuffisante)" }
catch { Write-Output "   -> refusé : $($_.Exception.Message)" }

Write-Output "`n2) sc.exe stop"
sc.exe stop $serviceName | Select-String -Pattern 'ÉCHEC|FAILED|1052|STATE' | ForEach-Object { Write-Output "   $_" }

Write-Output "`n3) taskkill /F sur chaque processus CoreGuard.Service.exe"
Get-Process -Name 'CoreGuard.Service' -ErrorAction SilentlyContinue | ForEach-Object {
    $out = taskkill /PID $_.Id /F 2>&1 | Out-String
    Write-Output ("   PID {0} : {1}" -f $_.Id, $out.Trim())
}

Start-Sleep -Seconds 8
$after = Get-Service -Name $serviceName
Write-Output "`nÉtat 8 s plus tard : $($after.Status)"
Get-Process -Name 'CoreGuard.Service' -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ("   processus actif : PID {0}" -f $_.Id) }
Write-Output "Journal du watchdog : $env:ProgramData\CoreGuard\watchdog.log (lisible en administrateur)"
