$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $projectRoot '.env'
if (-not (Test-Path -LiteralPath $envFile)) {
  throw "Arquivo .env não encontrado em $projectRoot"
}

$settings = @{}
foreach ($line in Get-Content -LiteralPath $envFile) {
  if ($line -match '^\s*([A-Z_]+)\s*=\s*(.*?)\s*$' -and -not $matches[1].StartsWith('#')) {
    $settings[$matches[1]] = $matches[2].Trim('"').Trim("'")
  }
}

foreach ($key in @('DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD')) {
  if (-not $settings[$key]) {
    throw "A configuração $key está ausente no .env"
  }
}

$defaultPgDump = 'C:\Program Files\PostgreSQL\19\bin\pg_dump.exe'
$pgDump = if ($env:PG_DUMP_PATH) { $env:PG_DUMP_PATH } else { $defaultPgDump }
if (-not (Test-Path -LiteralPath $pgDump)) {
  throw "pg_dump.exe não encontrado. Defina PG_DUMP_PATH ou instale o PostgreSQL."
}

$backupDir = Join-Path $env:LOCALAPPDATA 'kad-padaria\backups'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupFile = Join-Path $backupDir "$($settings['DB_NAME'])-$stamp.dump"

$env:PGPASSWORD = $settings['DB_PASSWORD']
try {
  & $pgDump --host $settings['DB_HOST'] --port $settings['DB_PORT'] --username $settings['DB_USER'] --dbname $settings['DB_NAME'] --format=custom --file $backupFile
  if ($LASTEXITCODE -ne 0) {
    throw "pg_dump terminou com código $LASTEXITCODE"
  }
} catch {
  if (Test-Path -LiteralPath $backupFile) {
    Remove-Item -LiteralPath $backupFile -Force
  }
  throw
} finally {
  Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
}

Write-Output "Backup concluído: $backupFile"
