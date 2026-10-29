# Install / uninstall the WeChat reader plugin for DeepSeek Harness.
# ASCII-only on purpose: Windows PowerShell 5.1 misreads BOM-less UTF-8 scripts.
#
#   powershell -ExecutionPolicy Bypass -File install.ps1
#   powershell -ExecutionPolicy Bypass -File install.ps1 -Uninstall
param(
    [string]$Source = $PSScriptRoot,
    [string]$Profile = "desktop",
    [switch]$Uninstall,
    [switch]$SkipCopy
)

$ErrorActionPreference = 'Stop'

$dshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $env:USERPROFILE '.dsh' }
$pluginDir = Join-Path $dshHome 'plugins\wechat-reader'
$profileDir = Join-Path $dshHome "profiles\$Profile"
$patchFile = Join-Path $profileDir 'cordis.patch.yml'
$entryId = 'tool-wechat-reader'
$entryPath = (Join-Path $pluginDir 'lib\index.js') -replace '\\', '/'

if (-not (Test-Path -LiteralPath $profileDir)) {
    throw "Profile not found: $profileDir"
}

function Read-Patch {
    if (Test-Path -LiteralPath $patchFile) {
        return [System.IO.File]::ReadAllText($patchFile, [System.Text.Encoding]::UTF8)
    }
    return ''
}

function Write-Patch([string]$Text) {
    if (Test-Path -LiteralPath $patchFile) {
        $stamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        Copy-Item -LiteralPath $patchFile -Destination "$patchFile.bak-$stamp" -Force
    }
    [System.IO.File]::WriteAllText($patchFile, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

function Remove-Entry([string]$Text) {
    # Drop one "- insert:" block whose body contains our id. Blocks start at column 0.
    $lines = $Text -split "`r?`n"
    $out = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $lines.Count) {
        if ($lines[$i] -match '^-\s') {
            $j = $i + 1
            while ($j -lt $lines.Count -and $lines[$j] -notmatch '^-\s') { $j++ }
            $block = $lines[$i..($j - 1)]
            if (($block -join "`n") -notmatch [regex]::Escape($entryId)) {
                foreach ($l in $block) { $out.Add($l) }
            }
            $i = $j
        } else {
            $out.Add($lines[$i])
            $i++
        }
    }
    return ($out -join "`n")
}

if ($Uninstall) {
    $text = Read-Patch
    if ($text -match [regex]::Escape($entryId)) {
        Write-Patch (Remove-Entry $text).TrimEnd() + "`n"
        Write-Host "Removed patch entry '$entryId'."
    } else {
        Write-Host "Patch entry '$entryId' not present."
    }
    if (Test-Path -LiteralPath $pluginDir) {
        Remove-Item -LiteralPath $pluginDir -Recurse -Force
        Write-Host "Removed $pluginDir"
    }
    Write-Host 'Restart DeepSeek Harness to finish uninstalling.'
    return
}

# 1. copy files
if (-not $SkipCopy) {
    if ((Resolve-Path -LiteralPath $Source).Path -eq (Resolve-Path -LiteralPath $pluginDir -ErrorAction SilentlyContinue).Path) {
        Write-Host "Source is already the install target."
    } else {
        New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
        foreach ($sub in @('lib', 'locale', 'dev')) {
            $from = Join-Path $Source $sub
            if (Test-Path -LiteralPath $from) {
                Copy-Item -LiteralPath $from -Destination $pluginDir -Recurse -Force
            }
        }
        Copy-Item -LiteralPath (Join-Path $Source 'package.json') -Destination $pluginDir -Force
        if (Test-Path -LiteralPath (Join-Path $Source 'README.md')) {
            Copy-Item -LiteralPath (Join-Path $Source 'README.md') -Destination $pluginDir -Force
        }
        Write-Host "Copied plugin to $pluginDir"
    }
}

# 2. patch the profile
$text = Read-Patch
if ($text -match [regex]::Escape($entryId)) {
    Write-Host "Patch entry '$entryId' already present."
} else {
    if ($text.Trim().Length -eq 0) {
        $text = ''
    } elseif (-not $text.EndsWith("`n")) {
        $text += "`n"
    }
    $block = @"
# WeChat local chat reader (dsh-plugin-wechat-reader) -- added by install.ps1
- insert:
    - id: $entryId
      name: '$entryPath'
"@
    Write-Patch ($text + $block + "`n")
    Write-Host "Added patch entry '$entryId' -> $entryPath"
}

Write-Host ''
Write-Host 'Done. Restart DeepSeek Harness, then ask in a new session:'
Write-Host '  "看看我微信最近在聊什么"'
Write-Host ''
Write-Host 'Requirement: WeChat (Weixin.exe) must be running and logged in.'
