# Creates "BetterWhatsapp" shortcuts on the Desktop and in the Start menu and
# removes the old "WhatsApp (Anti-Delete)" ones.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = (Resolve-Path (Join-Path $here '..')).Path
$icon = Join-Path $root 'assets\BetterWhatsapp.ico'
$sh = New-Object -ComObject WScript.Shell
foreach ($dir in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))) {
  $old = Join-Path $dir 'WhatsApp (Anti-Delete).lnk'
  if (Test-Path $old) { Remove-Item $old; "removed $old" }
  $lnk = $sh.CreateShortcut((Join-Path $dir 'BetterWhatsapp.lnk'))
  $lnk.TargetPath = "$env:WINDIR\System32\wscript.exe"
  $lnk.Arguments = "`"$here\start.vbs`""
  $lnk.WorkingDirectory = $root
  $lnk.Description = 'WhatsApp Desktop with the BetterWhatsapp mod'
  $lnk.IconLocation = "$icon,0"
  $lnk.Save()
  "created $($lnk.FullName)"
}
