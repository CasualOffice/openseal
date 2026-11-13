# Prepare Adobe Acrobat Reader on a disposable GitHub Actions Windows runner for the HRD-03 check
# (docs/31 §Verification ladder, fixtures/interop/ACROBAT-CHECKLIST.md). Never run on a desktop:
# it changes machine-wide trust and Reader's policies (docs/04 rule 17).
#
#   pwsh -File tools/interop/acrobat-setup.ps1 -Packet fixtures/interop
#
# 1. Trust the packet's test root, non-interactively. Acrobat's own trusted-identity list
#    (addressbook.acrodata) has no documented import other than its dialog, so the root goes
#    into the machine's Windows root store and Reader is told to trust that store for
#    signatures and certified documents (iMSStoreTrusted = 0x62, Adobe's Preference Reference,
#    Security > Windows Integration). Equivalent to the checklist's step 2 for what Reader
#    shows; the fingerprint is checked against trust/FINGERPRINT.txt first.
# 2. Set verification as the checklist's step 3: verify on open, revocation checks must
#    succeed when possible, embedded long-term material always used.
# 3. Turn off what would block an unattended run: first-run screens, sign-in, upsell, the
#    default-app prompt, the updater, Protected Mode (the sandbox is not under test) and
#    JavaScript (no packet file has any).
param([Parameter(Mandatory = $true)][string]$Packet)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'acrobat-setup.ps1 runs only on a GitHub Actions runner (docs/04 rule 17)' }

$cer = Join-Path $Packet 'trust/openseal-interop-root.cer'
$line = [string](Get-Content (Join-Path $Packet 'trust/FINGERPRINT.txt') | Where-Object { $_ -like 'SHA-256 *' } | Select-Object -First 1)
$want = ($line -replace '^SHA-256 ', '' -replace ':', '').Trim().ToUpper()
$got = (Get-FileHash -Algorithm SHA256 -LiteralPath $cer).Hash.ToUpper()
if ($want -ne $got) { throw "root fingerprint $got is not the one in FINGERPRINT.txt ($want)" }
$imported = Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root
Write-Host "trusted root: $($imported.Subject) SHA-256 $got (LocalMachine\Root)"

function Set-Dword([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

# Reader keeps its preferences under one of two names, by installer: set both.
foreach ($product in 'Acrobat Reader', 'Adobe Acrobat') {
    $u = "HKCU:\Software\Adobe\$product\DC"
    $p = "HKLM:\SOFTWARE\Policies\Adobe\$product\DC\FeatureLockDown"
    # Trust the Windows root store for signatures and certified documents.
    Set-Dword "$u\Security\cASPKI\cMSCAPI_DirectoryProvider" 'iMSStoreTrusted' 0x62
    # Checklist step 3.
    Set-Dword "$u\Security\cDigSig" 'bValidateOnOpen' 1
    Set-Dword "$u\Security\cASPKI\cASPKI\cVerify" 'iReqRevCheck' 2
    Set-Dword "$u\Security\cASPKI\cAdobe_LTVProvider" 'iUseArchivedRevInfo' 2
    # Unattended: EULA accepted, no first-run, sign-in, upsell or default-app prompts.
    Set-Dword "$u\AdobeViewer" 'EULA' 1
    Set-Dword "$u\AdobeViewer" 'Launched' 1
    Set-Dword "$u\AVAlert\cCheckbox" 'iAppDoNotTakePDFOwnershipAtLaunch' 1
    Set-Dword "$u\AVAlert\cCheckbox" 'iAppDoNotTakePDFOwnershipAtLaunchWin10' 1
    Set-Dword "$u\AVGeneral" 'bEnableAV2' 0
    Set-Dword "$u\FTEDialog" 'iFTEVersion' 100
    Set-Dword "$u\FTEDialog" 'iLastCardShown' 0
    Set-Dword $p 'bEnableAV2Enterprise' 0
    Set-Dword $p 'bToggleFTE' 1
    Set-Dword $p 'bAcroSuppressUpsell' 1
    Set-Dword $p 'bIsSCReducedModeEnforcedEx' 1
    Set-Dword $p 'bDisablePDFHandlerSwitching' 1
    Set-Dword $p 'bUpdater' 0
    Set-Dword $p 'bUsageMeasurement' 0
    Set-Dword $p 'bProtectedMode' 0
    Set-Dword $p 'iProtectedView' 0
    Set-Dword $p 'bDisableJavaScript' 1
}
Write-Host 'Reader preferences set'

# A larger screen, so the Signature Panel's lines are not cut off (best effort: the runner's
# default is 1024x768, and not every image allows changing it).
try { Set-DisplayResolution -Width 1920 -Height 1080 -Force; Write-Host 'screen 1920x1080' }
catch { Write-Host "screen left as is: $($_.Exception.Message)" }
