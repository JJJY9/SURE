# SURE — per-user Windows uninstall.
#
#   & .\scripts\Uninstall-Sure.ps1
#   & .\scripts\Uninstall-Sure.ps1 -RemoveUserData
#   & .\scripts\Uninstall-Sure.ps1 -WhatIf
#
# =============================================================================
# The directory this removes from also holds the user's evidence
# =============================================================================
#
# `scripts/Install-Sure.ps1` installs into `%LOCALAPPDATA%\SURE\bin` because
# eight launcher scripts in this tree already resolve
# `%LOCALAPPDATA%\SURE\bin\sure.exe`.
# `crates/sure-core/src/paths/mod.rs` puts the user's durable evidence — `sure.db`,
# the history a verdict is read from — at `<per-user data>\SURE`, which on Windows
# is **the same directory**. So the normal state of that directory is:
#
#     %LOCALAPPDATA%\SURE\
#         bin\sure.exe     what the install wrote
#         sure.db          the user's evidence, which the install did not write
#
# An uninstaller that removed that directory would destroy the record SURE exists
# to keep, and it would do it in the name of tidying up. This one is built so
# that it *cannot*:
#
#   1. **There is no recursive delete in this file.** Not of the install root,
#      not of `bin\`, not of anything. A directory is removed only when it is
#      already empty, so a directory holding a file this install did not write
#      cannot be removed at all — the filesystem refuses, not this script's
#      judgement. `crates/sure-cli/tests/install_flow.rs` reads this file and
#      fails if the word `-Recurse` appears in it.
#   2. **A file is removed only if the install's own manifest records it *and*
#      its digest is still the digest the install wrote.** The manifest is the
#      answer to "how does it know which files it created": the installer writes
#      it, and nothing else in this repository writes one. A file whose bytes
#      changed since — a newer binary, a file the user replaced — is not what
#      this install wrote, so it is reported and left.
#   3. **`sure.db` is not in the manifest**, because the install never writes it.
#      It is therefore unreachable from the removal above, whatever it contains.
#      The only code path that can remove it is `-RemoveUserData`, which names it
#      individually and which defaults to off.
#   4. **With no manifest, it removes nothing at all.** "What did this install
#      create?" has no answer in that state, and a guessed answer is the defect.
#      It says what it found, leaves it, and exits 2 — `Cannot confirm` is a
#      result, and it is not a yes.
#
# =============================================================================
# The choice about user data, and what it is a choice between
# =============================================================================
#
#   (default)          the program is removed; the user's history is kept, is
#                      named in the output, and the one switch that removes it
#                      is named with it.
#   -RemoveUserData    the store and SQLite's two sidecars for it are removed as
#                      well — `sure.db`, `sure.db-wal`, `sure.db-shm` — by name,
#                      inside the install root only. Nothing else in the
#                      directory is touched, however it is named.
#
# The names are `crates/sure-core/src/paths/mod.rs`'s `STORE_FILE` plus the two
# files SQLite's WAL journal mode creates beside it. They are *checkable* rather
# than copied on faith: `crates/sure-cli/tests/install_flow.rs` reads the list
# below and fails if it stops matching that constant.
#
# The user-level settings file (`%APPDATA%\SURE\sure.yaml`, the *config*
# directory) is outside the install root. This script never removes a file
# outside the install root, so it names that file and leaves it; a person who
# wants it gone removes one file they can see the name of.
#
# =============================================================================
# What this deliberately does not do
# =============================================================================
#
# No directory walk, no registry key, no service, no scheduled task, no `PATH`
# edit by this script, and no administrator rights. Nothing was added to those
# places by the install and nothing is removed from them here. `-WhatIf` prints
# every removal it would make and makes none.

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    # The directory the install was made into. The default is the documented
    # per-user location, which is where `Install-Sure.ps1` puts it when it is
    # given nothing.
    [string] $InstallRoot = '',

    # Also remove the user's evidence. Off, so that the default answer to "what
    # happens to my history?" is "nothing".
    [switch] $RemoveUserData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([Parameter(Mandatory)][string] $Text)
    Write-Host ''
    Write-Host "== $Text"
}

function Write-Detail {
    param([Parameter(Mandatory)][string] $Text)
    Write-Host "   $Text"
}

function Stop-Uninstall {
    param([Parameter(Mandatory)][string] $Text)
    Write-Host ''
    Write-Host "STOPPED: $Text"
    exit 2
}

# What happened to one path, said in the words for what actually happened.
#
# `-WhatIf` makes `ShouldProcess` answer no, and a run that answered "SURE is
# uninstalled" after removing nothing would be the false green this repository's
# first rule is about. The three outcomes are therefore separate sentences, and
# which one is printed is decided by the thing that did it rather than by the
# caller's hope: [removed] happened, [would remove] is a dry run, and
# [not removed] is a confirmation that was declined here or by `$ConfirmPreference`.
function Write-Removal {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][bool] $Happened,
        [string] $Note = ''
    )
    if ($Happened) {
        Write-Detail "removed      $Path$Note"
    } elseif ($dryRun) {
        Write-Host "   would remove $Path$Note (-WhatIf: nothing was removed)"
    } else {
        Write-Host "   not removed  $Path$Note (the removal was not confirmed)"
    }
}

# The platform's per-user application-data directory.
#
# The same six lines as `Install-Sure.ps1`'s, and deliberately not shared through
# a third file: the two scripts have to work when someone has copied one of them
# somewhere, and a helper beside them would be the first thing left behind. They
# are held equal by a test rather than by hope — `install_flow.rs` compares the
# two functions' text, so a fix to one that is not made to the other reddens.
function Get-PerUserDataRoot {
    $root = $env:LOCALAPPDATA
    if (-not $root) { $root = [Environment]::GetFolderPath('LocalApplicationData') }
    if (-not $root) {
        Stop-Uninstall @"
this machine did not report a per-user application-data directory, so where SURE
was installed cannot be established. SURE stopped rather than look for a path
relative to the current directory, or guess one.
"@
    }
    return $root
}

# SHA-256 of a file, through .NET rather than through a module.
#
# Not `Get-FileHash`: it is a script function from `Microsoft.PowerShell.Utility`,
# and Windows PowerShell 5.1 does not define it at all when a PowerShell 7
# session has set `PSModulePath` and then started 5.1 — which is what a launcher,
# a hook or a build script does. This was measured; the measurement and the full
# explanation are beside `Install-Sure.ps1`'s copy of this function and in
# `crates/sure-cli/tests/install_flow.rs`. Every other command in either script
# still resolves in that environment, so this one absence would otherwise land on
# the comparison that decides whether a file is this install's to remove.
function Get-Sha256 {
    param([Parameter(Mandatory)][string] $Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = $hasher.ComputeHash($stream)
        } finally {
            $hasher.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

# Join path segments without letting a separator decision depend on the host.
#
# The manifest stores relative paths with backslashes. Splitting on either
# separator means a manifest written on one platform cannot produce a path
# component that is silently read as part of a name on another.
function Join-RelativeTo {
    param(
        [Parameter(Mandatory)][string] $Root,
        [Parameter(Mandatory)][string] $Relative
    )
    $current = $Root
    foreach ($segment in ($Relative -split '[\\/]')) {
        if ($segment -eq '' -or $segment -eq '.') { continue }
        $current = Join-Path $current $segment
    }
    return $current
}

# The files `-RemoveUserData` removes, by name. Nothing is found by searching.
#
# `sure.db` is `sure_core::paths::STORE_FILE`; the other two are what SQLite's
# WAL journal mode keeps beside a database while it is open. A list rather than
# a wildcard: `sure.db*` would also match a file a person made, and `.db` alone
# would match every database anyone ever put here.
$DataFileNames = @('sure.db', 'sure.db-wal', 'sure.db-shm')

# `-WhatIf` and nothing else. It is read once so that every sentence below can be
# written for the run that actually happened.
$dryRun = [bool]$WhatIfPreference

Write-Step 'SURE uninstaller (per-user, Windows)'
if ($dryRun) {
    Write-Detail '-WhatIf was passed: every removal below is printed and none is made.'
}

# -----------------------------------------------------------------------------
# 1. Where to look, and whether there is anything there at all.
# -----------------------------------------------------------------------------
if ($InstallRoot -eq '') {
    $InstallRoot = Join-Path (Get-PerUserDataRoot) 'SURE'
}
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
if (-not [System.IO.Path]::IsPathRooted($InstallRoot)) {
    Stop-Uninstall "-InstallRoot was given as '$InstallRoot', which is not an absolute path. A relative path would point at whatever directory this ran from."
}

$BinDirectory = Join-Path $InstallRoot 'bin'
$ManifestPath = Join-Path $InstallRoot 'install-manifest.json'
Write-Detail "install root $InstallRoot"

if (-not (Test-Path -LiteralPath $InstallRoot -PathType Container)) {
    Write-Step 'Nothing to remove'
    Write-Detail "there is no directory at $InstallRoot, so SURE is not installed here."
    Write-Detail 'Nothing was removed, and nothing was created.'
    exit 0
}

# -----------------------------------------------------------------------------
# 2. The manifest — the only thing that can say what the install created.
# -----------------------------------------------------------------------------
Write-Step 'What this install created'
$manifest = $null
if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
    try {
        # `-Encoding UTF8` because the manifest this reads was written as
        # BOM-less UTF-8; Install-Sure.ps1's `Read-PreviousManifest` carries the
        # measured account. Without it, 5.1's ANSI decode turns a non-ASCII
        # install root into mojibake, the parse fails, and this catch — meant
        # for a manifest someone edited — answers "no manifest" about one this
        # install wrote, leaving every file it created in place.
        $candidate = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        $candidate = $null
    }
    if ($null -ne $candidate -and $candidate.kind -eq 'sure-install-manifest') {
        $manifest = $candidate
        Write-Detail "manifest     $ManifestPath"
        Write-Detail "installed at $($manifest.installed_at)"
        Write-Detail "from archive $($manifest.archive)"
    }
}

if ($null -eq $manifest) {
    # The real case this script exists to get right: the directory holds files
    # the install never wrote — a store from a development build, a manifest
    # someone edited, a binary someone copied. There is no record of what was
    # created, so there is no file that can be removed on evidence.
    $strandedBinary = Join-Path $BinDirectory 'sure.exe'
    $found = @(Get-ChildItem -LiteralPath $InstallRoot -Force)
    Write-Detail 'manifest     none found, so which files the install created cannot be established'
    Write-Host ''
    Write-Host "   Files under $InstallRoot, all of them left alone:"
    foreach ($item in $found) {
        Write-Host "     $(if ($item.PSIsContainer) { $item.Name + '\' } else { $item.Name })"
    }
    if (Test-Path -LiteralPath $strandedBinary -PathType Leaf) {
        Write-Host ''
        Write-Host "   There is a program at $strandedBinary and no manifest that says this"
        Write-Host "   install put it there. It may have come from somewhere else."
    }
    Write-Host ''
    Write-Host '   Nothing was removed. Removing files here would mean deleting by guesswork,'
    Write-Host '   in a directory that also holds the history SURE exists to keep. If the'
    Write-Host '   program is one you want gone, remove the files named above yourself.'
    exit 2
}

# -----------------------------------------------------------------------------
# 3. The install's own files, each one checked against what the install wrote.
# -----------------------------------------------------------------------------
Write-Step 'Removing what this install wrote'
$kept = @()
$missing = @()
foreach ($record in @($manifest.files)) {
    $path = Join-RelativeTo -Root $InstallRoot -Relative $record.path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $missing += $record.path
        continue
    }
    $digest = Get-Sha256 -Path $path
    if ($digest -ne $record.sha256) {
        # The important case. A file at a path this install wrote, whose bytes are
        # not the bytes it wrote, is not this install's file any more: it may be
        # a newer binary, or something a person put there deliberately. It is
        # named, and it stays.
        $kept += [pscustomobject]@{ Path = $path; Why = "its contents are not the ones this install wrote (expected $($record.sha256), found $digest)" }
        continue
    }
    $gone = $PSCmdlet.ShouldProcess($path, 'Remove file installed by SURE')
    if ($gone) { Remove-Item -LiteralPath $path -Force }
    Write-Removal -Path $path -Happened $gone
}
foreach ($path in $missing) { Write-Detail "already gone $path" }
foreach ($item in $kept) { Write-Host "   kept         $($item.Path)"; Write-Host "                $($item.Why)" }

# A directory is removed only when it is empty, which is the whole mechanism:
# the removal is refused by the filesystem when anything is still in it, so no
# decision this script makes can reach a file it did not record. Deepest first,
# so `bin\` is considered after anything below it.
foreach ($relative in (@($manifest.directories) | Sort-Object -Property Length -Descending)) {
    if ([string]::IsNullOrWhiteSpace($relative)) { continue }
    $directory = Join-RelativeTo -Root $InstallRoot -Relative $relative
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
    $inside = @(Get-ChildItem -LiteralPath $directory -Force)
    if ($inside.Count -gt 0) {
        # Under `-WhatIf` the files are still there because nothing was removed,
        # not because they are somebody else's, and saying the second thing when
        # the first is true is the kind of sentence this repository calls a false
        # report even when nothing was damaged by it.
        if ($dryRun) {
            Write-Host "   would keep   $directory\ (-WhatIf: it still holds $(($inside | ForEach-Object { $_.Name }) -join ', '))"
        } else {
            Write-Host "   kept         $directory\"
            Write-Host "                it still holds $(($inside | ForEach-Object { $_.Name }) -join ', '), which this install did not write"
        }
        continue
    }
    $gone = $PSCmdlet.ShouldProcess($directory, 'Remove empty directory created by SURE')
    if ($gone) { Remove-Item -LiteralPath $directory -Force }
    Write-Removal -Path $directory -Happened $gone -Note ' (it was empty)'
}

# -----------------------------------------------------------------------------
# 4. The user's evidence — only when the caller asked for it, and only by name.
# -----------------------------------------------------------------------------
Write-Step 'Your history'
if ($RemoveUserData) {
    $dataFound = 0
    foreach ($name in $DataFileNames) {
        $path = Join-Path $InstallRoot $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $dataFound++
        $bytes = (Get-Item -LiteralPath $path).Length
        $gone = $PSCmdlet.ShouldProcess($path, 'Remove SURE history (-RemoveUserData)')
        if ($gone) { Remove-Item -LiteralPath $path -Force }
        Write-Removal -Path $path -Happened $gone -Note " ($bytes bytes)"
    }
    if ($dataFound -eq 0) { Write-Detail 'there was no stored history to remove' }
    if ($dryRun) {
        Write-Detail '-RemoveUserData was passed, and -WhatIf means the history above is still there.'
    } else {
        Write-Detail '-RemoveUserData was passed, so the history above is gone. It cannot be undone,'
        Write-Detail 'and nothing else in that directory was touched.'
    }
} else {
    $storePath = Join-Path $InstallRoot 'sure.db'
    if (Test-Path -LiteralPath $storePath -PathType Leaf) {
        $bytes = (Get-Item -LiteralPath $storePath).Length
        Write-Detail "kept         $storePath ($bytes bytes)"
        Write-Detail 'Your history is still there. Nothing removed it, and nothing will unless you'
        Write-Detail 'ask for it by name:'
        Write-Detail "  & '$(Join-Path $PSScriptRoot 'Uninstall-Sure.ps1')' -RemoveUserData"
    } else {
        Write-Detail 'there is no stored history at this location, and none was removed'
    }
}

# -----------------------------------------------------------------------------
# 5. The settings file, which is not in this directory and is not this script's.
# -----------------------------------------------------------------------------
$configRoot = $env:APPDATA
if (-not $configRoot) { $configRoot = [Environment]::GetFolderPath('ApplicationData') }
if ($configRoot) {
    $settingsFile = Join-Path (Join-Path $configRoot 'SURE') 'sure.yaml'
    if (Test-Path -LiteralPath $settingsFile -PathType Leaf) {
        Write-Detail "settings     $settingsFile"
        Write-Detail '             Your settings are kept, and are outside this directory. SURE does not'
        Write-Detail '             remove files outside the directory it installed into. Remove that one'
        Write-Detail '             file yourself if you want your settings gone as well.'
    }
}

# -----------------------------------------------------------------------------
# 6. The manifest itself. Kept when anything it recorded is still here: it is
#    the only record of what is, and throwing it away would make a second run
#    able to remove less than this one did.
# -----------------------------------------------------------------------------
Write-Step 'Done'
if ($kept.Count -eq 0 -and -not $dryRun) {
    if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
        $gone = $PSCmdlet.ShouldProcess($ManifestPath, "Remove SURE's install manifest")
        if ($gone) { Remove-Item -LiteralPath $ManifestPath -Force }
        Write-Removal -Path $ManifestPath -Happened $gone
    }
    if (Test-Path -LiteralPath $InstallRoot -PathType Container) {
        $left = @(Get-ChildItem -LiteralPath $InstallRoot -Force)
        if ($left.Count -gt 0) {
            Write-Detail "$InstallRoot was left in place; it still holds:"
            foreach ($item in $left) {
                Write-Host "                $(if ($item.PSIsContainer) { $item.Name + '\' } else { $item.Name })"
            }
        } else {
            Write-Detail "$InstallRoot is empty. It was not removed: it is the per-user data directory"
            Write-Detail 'for this application, and a later install, or SURE itself, will use it.'
        }
    }
    Write-Detail 'SURE is uninstalled. No PATH entry was removed, because none was added.'
} elseif ($dryRun) {
    Write-Detail 'This was a dry run (-WhatIf). Nothing was removed and nothing was changed;'
    Write-Detail 'run it again without -WhatIf to make the removals printed above.'
} else {
    Write-Detail "$ManifestPath was kept: it records files that are still here, and it is the only"
    Write-Detail 'thing that can say which of them the install wrote. Run this again after those'
    Write-Detail 'files are gone to finish the removal.'
    Write-Detail 'SURE is uninstalled; the files named above were left where they are.'
}
exit 0
