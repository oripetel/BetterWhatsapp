# Starts WhatsApp Desktop with the BetterWhatsapp mod.
#
# WhatsApp's UI runs in WebView2. For a few seconds this sets the user env var
# WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS so WhatsApp's WebView2 opens a DevTools
# port on 127.0.0.1, then clears it again (other WebView2 apps launched in that
# window would get the port too, so the window is kept short). launcher.mjs
# then attaches and injects inject.js. If the mod is already running, this just
# brings WhatsApp to the front.
$ErrorActionPreference = 'Stop'
$here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$app   = 'shell:AppsFolder\5319275A.WhatsAppDesktop_cv1g1gvanyjgm!App'
$state = Join-Path $env:LOCALAPPDATA 'BetterWhatsapp'
New-Item -ItemType Directory -Force $state | Out-Null
$pidFile = Join-Path $state 'launcher.pid'
$logFile = Join-Path $state 'launcher.log'

if (Test-Path $pidFile) {
  $old = Get-Process -Id ([int](Get-Content $pidFile)) -ErrorAction SilentlyContinue
  if ($old -and $old.ProcessName -eq 'node' -and (Get-Process WhatsApp.Root -ErrorAction SilentlyContinue)) {
    Start-Process $app
    exit
  }
}

Add-Type -Namespace WaAd -Name Native -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern System.IntPtr SendMessageTimeout(System.IntPtr h, uint m, System.UIntPtr w, string l, uint f, uint t, out System.UIntPtr r);'
function Send-EnvChanged { $r = [UIntPtr]::Zero; [WaAd.Native]::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$r) | Out-Null }

$port = Get-Random -Minimum 20000 -Maximum 60000
Get-Process WhatsApp.Root -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 1500
try {
  [Environment]::SetEnvironmentVariable('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', "--remote-debugging-port=$port", 'User')
  Send-EnvChanged
  Start-Process $app
  $up = $false
  for ($i = 0; $i -lt 60 -and -not $up; $i++) {
    Start-Sleep -Milliseconds 500
    try { Invoke-RestMethod "http://127.0.0.1:$port/json/version" -TimeoutSec 1 | Out-Null; $up = $true } catch {}
  }
} finally {
  [Environment]::SetEnvironmentVariable('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', $null, 'User')
  Send-EnvChanged
}
if (-not $up) { "$(Get-Date -Format o) WhatsApp started without the DevTools port; mod not active" | Add-Content $logFile; exit 1 }

$node = (Get-Command node -ErrorAction Stop).Source
$p = Start-Process $node -ArgumentList "`"$here\..\src\launcher.mjs`" --port $port" -WindowStyle Hidden -PassThru `
  -RedirectStandardOutput $logFile -RedirectStandardError (Join-Path $state 'launcher.err.log')
$p.Id | Set-Content $pidFile
