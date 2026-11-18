# Run from the root of microclimate_monitoring_system in VS Code PowerShell.
# All real keys and the demo database are placed outside the repository.
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath '.\app\crypto_fields.py')) { throw 'Run from the repository root after applying the patch.' }
$python = (Resolve-Path '.\.venv\Scripts\python.exe').Path
$env:PYTHONUTF8 = '1'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    $gitCommand = Get-Command git -ErrorAction Stop
    $gitRoot = Split-Path (Split-Path $gitCommand.Source -Parent) -Parent
    $gitOpenSsl = Join-Path $gitRoot 'usr\bin\openssl.exe'
    if (Test-Path -LiteralPath $gitOpenSsl) { $env:Path = (Split-Path $gitOpenSsl -Parent) + ';' + $env:Path }
}
if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) { throw 'OpenSSL 3 was not found in PATH.' }
$pr9Dir = Join-Path $env:LOCALAPPDATA 'ProtectedSoftwareLab\microclimate_monitoring_system\pr9'
$repo = (Get-Location).Path.TrimEnd('\')
$fullSecretDir = [IO.Path]::GetFullPath($pr9Dir)
if ($fullSecretDir.Equals($repo, [StringComparison]::OrdinalIgnoreCase) -or $fullSecretDir.StartsWith($repo + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Secret directory must be outside Git.' }
New-Item -ItemType Directory -Path $pr9Dir -Force | Out-Null
# Restrict this dedicated lab directory to the current Windows account.
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $pr9Dir
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
$prop = [System.Security.AccessControl.PropagationFlags]::None
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, $full, $inherit, $prop, $allow))
Set-Acl -LiteralPath $pr9Dir -AclObject $acl
$pr9KeyFile = Join-Path $pr9Dir 'data-key.hex'
if (-not (Test-Path -LiteralPath $pr9KeyFile)) {
    & $python -c 'from pathlib import Path; from secrets import token_hex; import sys; f=Path(sys.argv[1]).open("x", encoding="ascii"); f.write(token_hex(32)); f.close()' $pr9KeyFile
    if ($LASTEXITCODE -ne 0) { throw 'Key creation failed.' }
}
$keyAcl = Get-Acl -LiteralPath $pr9KeyFile
$keyAcl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($keyAcl.Access)) { [void]$keyAcl.RemoveAccessRuleAll($rule) }
$keyAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, $full, $allow))
Set-Acl -LiteralPath $pr9KeyFile -AclObject $keyAcl
$env:PR9_DATA_KEY_HEX = [IO.File]::ReadAllText($pr9KeyFile).Trim()
$runDir = Join-Path $pr9Dir ('run-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDir | Out-Null
$database = Join-Path $runDir 'application.sqlite3'
# Evidence remains public only because all values in the experiment are synthetic.
$evidence = Join-Path $repo 'docs\pr9-evidence'
if (Test-Path -LiteralPath $evidence) {
    # Preserve prior observations outside Git before a repeat run.
    Move-Item -LiteralPath $evidence -Destination (Join-Path $runDir 'previous-evidence')
}
New-Item -ItemType Directory -Path $evidence | Out-Null

function Save-Result($name, $lines) {
    $lines | Set-Content -LiteralPath (Join-Path $evidence $name) -Encoding UTF8
    $lines | Write-Output
}
function Invoke-CheckedPython([string[]]$arguments) {
    $result = & $python @arguments
    if ($LASTEXITCODE -ne 0) { throw ('Python failed: ' + ($arguments -join ' ')) }
    $result
}

Write-Host '=== 1. Environment and key access ==='
$versions = @(& $python --version; & $python -c 'import cryptography; print("cryptography", cryptography.__version__)'; git --version; openssl version)
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL 3 is required.' }
$versions += @('AES key: set (value not displayed)', 'Key file ACL:', (Get-Acl -LiteralPath $pr9KeyFile).AccessToString)
Save-Result 'environment.txt' $versions

Write-Host '=== 2. Hash, HMAC and AES-GCM ==='
$csvPath = Join-Path $evidence 'pr9-observations.csv'
$rowsText = Invoke-CheckedPython @('experiment_pr9.py')
$rowsText | Set-Content -LiteralPath $csvPath -Encoding UTF8
$rows = @(Import-Csv -LiteralPath $csvPath)
$expected = @{ A0='equal'; A1='different'; A2='equal'; A3='accepted'; A4='rejected'; B0='restored'; B1='rejected'; B2='rejected'; B3='rejected'; B4='rejected'; B5='rejected' }
$protocol = @('Observations: ' + $rows.Count)
$ok = $rows.Count -eq 45
foreach ($code in ($expected.Keys | Sort-Object)) {
    $group = @($rows | Where-Object series -eq $code)
    $matching = @($group | Where-Object outcome -eq $expected[$code]).Count
    $required = if ($code.StartsWith('A')) { 3 } else { 5 }
    $protocol += "$code | $($expected[$code]) | $matching/$required (rows=$($group.Count))"
    if ($matching -ne $required -or $group.Count -ne $required) { $ok = $false }
}
$baseRows = @($rows | Where-Object series -eq 'B0')
$unique = @($baseRows.detail | Sort-Object -Unique).Count
$protocol += "Distinct nonces: $unique/5"
foreach ($row in $baseRows) {
    $calculated = 10 + 4 * [Math]::Ceiling(([int]$row.plain_bytes + 28) / 3.0)
    $protocol += "B0 trial $($row.trial) | UTF-8=$($row.plain_bytes) | measured=$($row.stored_chars) | calculated=$calculated"
    if ([int]$row.stored_chars -ne $calculated) { $ok = $false }
}
Save-Result 'protocol.txt' $protocol
if (-not $ok -or $unique -ne 5) { throw 'Unexpected observation; evidence preserved.' }

Write-Host '=== 3. Individual profile P1 ==='
Save-Result 'profile-p1.txt' (Invoke-CheckedPython @('experiment_pr9.py','--profile'))

Write-Host '=== 4. X.509 ==='
$certOutput = & $python cert_pr9.py --directory (Join-Path $runDir 'cert')
$certExit = $LASTEXITCODE
Save-Result 'certificate.txt' $certOutput
if ($certExit -ne 0) { throw 'Unexpected certificate result; evidence preserved.' }

Write-Host '=== 5. SQLite persistence, RBAC and startup ==='
$integration = @('Process 1: create')
$integration += Invoke-CheckedPython @('demo_v09.py','create','--db',$database)
$integration += 'Process 2: read after restart'
$integration += Invoke-CheckedPython @('demo_v09.py','read','--db',$database)
try {
    Remove-Item Env:PR9_DATA_KEY_HEX -ErrorAction SilentlyContinue
    $integration += 'Process 3: missing key'
    $out = & $python demo_v09.py startup
    $exit = $LASTEXITCODE
    $integration += $out; $integration += "Exit: $exit"
    if ($exit -ne 2) { throw 'Missing-key startup should fail.' }
    $env:PR9_DATA_KEY_HEX = 'abc'
    $integration += 'Process 4: malformed key'
    $out = & $python demo_v09.py startup
    $exit = $LASTEXITCODE
    $integration += $out; $integration += "Exit: $exit"
    if ($exit -ne 2) { throw 'Malformed-key startup should fail.' }
} finally {
    $env:PR9_DATA_KEY_HEX = [IO.File]::ReadAllText($pr9KeyFile).Trim()
    Save-Result 'integration.txt' $integration
}
$integration += 'Process 5: restored key, authorized read'
$integration += Invoke-CheckedPython @('demo_v09.py','read','--db',$database)
Save-Result 'integration.txt' $integration

Write-Host '=== 6. New tests and full regression ==='
$newTests = & $python -m pytest -q tests/test_v09.py
$newExit = $LASTEXITCODE
Save-Result 'new-tests.txt' $newTests
if ($newExit -ne 0) { throw 'New tests failed.' }
$allTests = & $python -m pytest -q
$allExit = $LASTEXITCODE
Save-Result 'regression.txt' $allTests
if ($allExit -ne 0) { throw 'Regression failed.' }
Write-Host 'PR9 completed. Evidence: docs/pr9-evidence. No commit was created.'
