# SURE — per-user Windows install from a release archive.
#
#   & .\scripts\Install-Sure.ps1 -Archive <path>\sure-<version>-x86_64-pc-windows-msvc.zip
#
# The archive is the one `scripts/Build-Release.ps1` produces, laid out as
# `docs/development/RELEASE_PROCESS.md` records: one top-level directory of the
# archive's own name holding `sure.exe`, `LICENSE` and `RELEASE.txt`, and a
# `<archive>.sha256` beside the archive in `sha256sum` format.
#
# =============================================================================
# Where this installs, and why that is not a free choice
# =============================================================================
#
# `%LOCALAPPDATA%\SURE\bin\sure.exe`. The destination is already in use by eight
# launcher scripts in five integration packages that this task does not own, and
# all of them resolve it in the order `$env:SURE_BIN` -> `PATH` -> here:
#
#   integrations/agent-plugin/scripts/install.ps1   (line 7)
#   integrations/claude-code/scripts/install.ps1    (line 7)
#   integrations/claude-code/scripts/sure-hook.ps1  (line 26)
#   integrations/claude-code/scripts/sure-mcp.ps1   (line 16, and with a
#       `[Environment]::GetFolderPath('LocalApplicationData')` fallback when
#       `%LOCALAPPDATA%` is unset)
#   integrations/codex/scripts/sure-hook.ps1        (line 26)
#   integrations/copilot/scripts/sure-hook.ps1      (line 26)
#   integrations/cursor/scripts/install.ps1         (line 7)
#   integrations/cursor/scripts/sure-hook.ps1       (line 26)
#
# A different destination would be a binary those integrations cannot find, so
# this is a place the tree already agreed on rather than one chosen here.
# `grep -rn LOCALAPPDATA integrations/` is what finds them: among its results are
# these eight launcher scripts under five package directories, and counting them
# is the search to repeat before moving this. (The search returns more than these
# eight — 26 files on 2026-09-21 — so it is the launchers in its output that this
# list is. The rest are READMEs and command files that mention the variable, plus
# the uninstall scripts, which name the directory to remove from rather than the
# binary to resolve: `grep -rln LOCALAPPDATA integrations --include='*.ps1'`
# returns ten, and these eight are the ones that resolve `sure.exe`.) The `.sh`
# launchers beside these resolve `$SURE_BIN` and `PATH` instead, which is right
# for Unix and is not another opinion about the Windows location.
#
# The known-folder lookup is not hand-rolled, and the reason is written down in
# `crates/sure-core/src/paths/mod.rs:1-14`: a bare read of `%LOCALAPPDATA%`
# "would quietly produce a *relative* path whenever that variable is unset".
# `Get-PerUserDataRoot` below is the same two-step that `sure-mcp.ps1:16` uses —
# the variable first, the platform's own answer second — because a PowerShell
# script cannot call `SHGetKnownFolderPath` directly any more than the Rust core
# can (`unsafe_code = "forbid"`), and `.NET`'s `GetFolderPath` is that call.
#
# =============================================================================
# The directory this installs into is ALSO the user's data directory
# =============================================================================
#
# `crates/sure-core/src/paths/mod.rs` resolves the user's durable evidence —
# the `sure.db` history a verdict is read from — to `<per-user data>\SURE`
# (`APP_DIR`, line 60), which on Windows is this same directory. So the normal
# case on a machine where SURE has been used is:
#
#     %LOCALAPPDATA%\SURE\
#         bin\sure.exe     what this install writes
#         sure.db          the user's evidence; NOT this install's to remove
#
# This installer therefore writes exactly four paths:
#
#     bin\sure.exe, bin\LICENSE, bin\RELEASE.txt   copied out of the archive
#     install-manifest.json                        what it created, with each
#                                                  file's digest, so that
#                                                  removal can be exact
#
# and it **refuses** to overwrite a file that is already there unless the
# previous install's own manifest says the file is its (same path, same
# digest), or `-Force` says to replace it anyway. `-Force` names what it is
# about to replace before it does. `scripts/Uninstall-Sure.ps1` reads the
# manifest; nothing removes a file by walking a directory.
#
# =============================================================================
# What this deliberately does not do
# =============================================================================
#
# * No administrator rights, no elevation request, no `HKLM`, no service, no
#   scheduled task, no `PATH` write — machine or user. `CLAUDE.md` requires
#   per-user installation without administrator rights, and criterion 1 asks
#   for no hidden background service. `PATH` is *reported* rather than changed:
#   see the last block of output, and `docs/development/INSTALL_WINDOWS.md`.
# * No symlink. `CLAUDE.md` prefers copy/render/install flows on Windows unless
#   Developer Mode or administrator capability is explicitly detected, and a
#   release binary is copied rather than linked here.
# * No signing claim, and no signing *reading* either. The output's last block
#   reports the `signature` line out of the archive's own `RELEASE.txt` - the
#   file the build that measured it wrote, which this install copies to
#   `bin\RELEASE.txt` - rather than stating a state this script has not read.
#   An installer that printed its own sentence about the bytes would be the
#   unmeasured claim `P15-T012` took out of `scripts/Build-Release.ps1`, one
#   step further down the pipe, and it would be read by the one person who
#   cannot check it. `docs/development/RELEASE_PROCESS.md`'s `## Signing` is
#   the authoritative statement and says what may and may not be written.
#
# =============================================================================
# What reddens this script
# =============================================================================
#
#   * an archive that does not match its `.sha256` -> refuses before extracting;
#   * a `.sha256` that is missing, empty, has more than one line, carries a CR,
#     a BOM, or a name that is not this archive's -> refuses;
#   * an archive whose entries would extract outside the scratch directory
#     (a `..` or absolute entry name) -> refuses;
#   * an archive that is not one top-level directory named after itself, or one
#     without `sure.exe` in it -> refuses;
#   * a file already at a destination that this install did not write ->
#     refuses unless `-Force`, naming the file;
#   * `-InstallRoot` that is not an absolute path -> refuses.
#
# `crates/sure-cli/tests/install_flow.rs` drives this script against archives it
# builds itself, and is where the properties above are measured rather than
# asserted by this comment.

[CmdletBinding()]
param(
    # The release archive. Required, and named rather than discovered: a script
    # that picked "the zip in the current directory" would install whatever a
    # download folder happened to hold.
    [Parameter(Mandatory = $true)]
    [string] $Archive,

    # The `sha256sum`-format checksum file. Defaults to `<archive>.sha256`, which
    # is where `Build-Release.ps1` writes it, and is read rather than skipped:
    # there is no switch to install an unverified archive, because a check that
    # can be turned off is not a check.
    [string] $Checksum = '',

    # Where to install. The default is the documented per-user location. It is a
    # parameter so that the tests and a person who wants a private copy can name
    # one, in the same way `sure --store-dir` lets a caller name a store: the
    # location comes from the caller's own argument vector.
    [string] $InstallRoot = '',

    # Where the archive is unpacked. Defaults to a fresh directory under the
    # platform's temporary directory, and it is removed at the end.
    [string] $ScratchDirectory = '',

    # Replace files that are already at the destinations this install would
    # write, and that this install's manifest does not claim.
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# `docs/development/WINDOWS.md` and `CLAUDE.md` put this repository's scripts on
# PowerShell 7+, and `scripts/Build-Release.ps1` needs nothing here. This line is
# for the other host a person may reach for: Windows PowerShell 5.1 does not load
# `System.IO.Compression.FileSystem` by default, and without it the unpack step
# stops at "Unable to find type [System.IO.Compression.ZipFile]" - a message
# about a type rather than about the thing that is wrong. On 7 the assembly is
# already there and this is a no-op.
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

function Write-Step {
    param([Parameter(Mandatory)][string] $Text)
    Write-Host ''
    Write-Host "== $Text"
}

function Write-Detail {
    param([Parameter(Mandatory)][string] $Text)
    Write-Host "   $Text"
}

function Stop-Install {
    param([Parameter(Mandatory)][string] $Text)
    Write-Host ''
    Write-Host "STOPPED: $Text"
    exit 2
}

# The platform's per-user application-data directory.
#
# The variable first and the platform's own known-folder answer second, which is
# `integrations/claude-code/scripts/sure-mcp.ps1:16`'s order. Read that line
# before changing this one: the eight launchers listed at the top of this file
# resolve the install location this way, and one that resolved it differently
# would look at a directory nothing is installed in.
function Get-PerUserDataRoot {
    $root = $env:LOCALAPPDATA
    if (-not $root) { $root = [Environment]::GetFolderPath('LocalApplicationData') }
    if (-not $root) {
        Stop-Install @"
this machine did not report a per-user application-data directory, so there is
no documented place to install to and no place to guess at. SURE stopped rather
than write to a path relative to the current directory.

  %LOCALAPPDATA%                     $($env:LOCALAPPDATA)
  GetFolderPath(LocalApplicationData) $([Environment]::GetFolderPath('LocalApplicationData'))
"@
    }
    return $root
}

# SHA-256 of a file, through .NET rather than through a module.
#
# `Get-FileHash` is the obvious call and it is deliberately not used here. It is
# a *script function* that lives in `Microsoft.PowerShell.Utility`, so it exists
# only in a host that brings that module up. Where it does not, the failure lands
# on the one step that is the integrity check, and it lands there as "not
# recognized as the name of a cmdlet" — which reads like a typo rather than like
# an environment, and is the reason this is written down rather than assumed.
#
# That it does not come up here is measured rather than imagined. With a
# throwaway diagnostic at the top of this function, a run of
# `crates/sure-cli/tests/install_flow.rs` — the suite that starts this script the
# way a launcher does — reported this from the child process itself, four times:
#
#     pshome  = C:\Windows\System32\WindowsPowerShell\v1.0
#     version = 5.1.26100.9444
#     command = ABSENT
#     psmodulepath:
#        [C:\Users\lishi\Documents\PowerShell\Modules]
#        [C:\Program Files\PowerShell\Modules]
#        [c:\program files\windowsapps\microsoft.powershell_7.6.6.0_x64__8wekyb3d8bbwe\Modules]
#        [C:\Program Files\WindowsPowerShell\Modules]
#        [C:\Windows\system32\WindowsPowerShell\v1.0\Modules]
#     call    = THREW System.Management.Automation.CommandNotFoundException
#
# The child inherits the PowerShell 7 session's `PSModulePath` verbatim — the
# `windowsapps` entry is a PowerShell 7 module directory — and that is the
# consistent explanation for the module not coming up. It is named here as an
# explanation and not as a proven mechanism: the shadowing step itself was not
# isolated, and a Windows PowerShell 5.1 started by hand from a PowerShell 7
# session did bring `Get-FileHash` up. What the same run *did* establish is that
# nothing else here depends on the answer: `Get-Content`, `ConvertFrom-Json`,
# `Get-ChildItem`, `Copy-Item` and `ConvertTo-Json` are cmdlets from assemblies
# the console host loads at startup and do not care what is on `PSModulePath`,
# and every one of them served this install in that same process.
#
# `[System.Security.Cryptography.SHA256]` is the same algorithm from the same
# place — `Get-FileHash` calls it — and it depends on no module being findable.
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
    # `BitConverter` spells it uppercase with dashes; `sha256sum` and the
    # `.sha256` file this repository writes both want lowercase with none.
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

# Read the `signature` token out of a `RELEASE.txt`.
#
# The top of that file is a title line followed by an indented block of
# `label  value` lines, and the prose sections come after it at column 0. The
# block is therefore the run of indented lines, and the label is looked for only
# inside it: everything below is sentences, and several of them contain the word
# "signature" without being a statement of one.
#
# This function's text is **identical** in `scripts/Build-Release.ps1` and
# `scripts/Install-Sure.ps1`, which are the two things that read this file. There
# is no shared module between them, and two copies of a reader are two readers
# unless something holds them together, so
# `crates/sure-testkit/tests/signing_status.rs` compares the two definitions
# character for character and fails if either is edited alone. A fix to one has
# to be a fix to both, or it is not a fix.
#
# It returns the token, or the empty string when there is no line - including
# when the file is not there at all. The empty string is not a state: it means
# the state was not stated, and callers report it as such.
function Get-StatedSignature {
    param([Parameter(Mandatory)][string] $Path)
    $token = ''
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $token }
    $inBlock = $false
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($line.Trim() -eq '') { continue }
        $indented = $line.StartsWith(' ') -or $line.StartsWith("`t")
        if (-not $indented) {
            if ($inBlock) { break }
            continue
        }
        $inBlock = $true
        if ($line.Trim() -match '^signature\s+(\S+)') { $token = $Matches[1]; break }
    }
    return $token
}

# Join path segments without letting a separator decision depend on the host.
#
# The manifest stores relative paths with backslashes, and this is what turns one
# back into a location. Splitting on both separators means a manifest written on
# one platform cannot produce a path component that is silently treated as part
# of a name on another.
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

# The checksum line, read as bytes.
#
# The format is `Build-Release.ps1`'s and `RELEASE_PROCESS.md`'s: one line,
# `<64 lowercase hex><two spaces><file name>`, ASCII, no BOM, LF. Each of those
# is checked rather than assumed, because the defect the CR check exists for was
# measured: `Set-Content` wrote `...zip\r\n`, every Windows tool read it
# happily, and `sha256sum -c` answered `'sure-....zip'\r': No such file or
# directory`. A checksum nobody else can read is not an integrity check.
function Read-ChecksumLine {
    param([Parameter(Mandatory)][string] $Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) { Stop-Install "the checksum file $Path is empty." }
    if ($bytes[0] -eq 0xEF) { Stop-Install "the checksum file $Path starts with a BOM, which sha256sum reads as part of the digest." }
    if ($bytes -contains 13) {
        Stop-Install "the checksum file $Path contains a CR at byte $([Array]::IndexOf($bytes, [byte]13)); sha256sum reads it as part of the file name."
    }
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $lines = @($text -split "`n" | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -ne 1) {
        Stop-Install "the checksum file $Path has $($lines.Count) non-empty lines; a release checksum file has exactly one."
    }
    if ($lines[0] -match '^([0-9a-f]{64})  (.+)$') {
        return [pscustomobject]@{ Digest = $Matches[1]; FileName = $Matches[2] }
    }
    # Uppercase hex, one space, a `*` binary marker or a trailing comment all
    # land here. The format is not a preference: `sha256sum -c` is the reader
    # this file exists for, and it accepts exactly one spelling of it.
    Stop-Install "the checksum file $Path is not in sha256sum format. Expected '<64 lowercase hex><two spaces><file name>', read: '$($lines[0])'."
}

# An entry the archive must not be allowed to write: one whose own name climbs
# out of the extraction directory or starts at a drive.
#
# A release archive is a file that arrived from somewhere, and a ZIP entry name
# is text inside it. `..\..\Windows\System32\x.dll` is a name, not a path the
# extractor has any business following, so each one is resolved and compared
# against the extraction root before anything is written.
function Assert-EntryIsInside {
    param(
        [Parameter(Mandatory)][string] $EntryName,
        [Parameter(Mandatory)][string] $Root
    )
    $prefix = [System.IO.Path]::GetFullPath($Root)
    if (-not $prefix.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $prefix = $prefix + [System.IO.Path]::DirectorySeparatorChar
    }
    $target = [System.IO.Path]::GetFullPath((Join-Path $prefix $EntryName))
    if (-not $target.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-Install "the archive holds an entry named '$EntryName', which unpacks to $target, outside the directory it was unpacked into ($prefix). SURE stopped rather than write there."
    }
}

# Read the manifest a previous install wrote, or nothing.
#
# `-Encoding UTF8` because this is the file `[System.IO.File]::WriteAllText`
# below writes, which is UTF-8 without a BOM. Windows PowerShell 5.1's default
# reader decodes that as the machine's ANSI code page, and an `install_root`
# holding a non-ASCII user name right before a separator — the shape of
# `C:\Users\<name>\AppData\...` — comes back as mojibake that the parse then
# rejects. Measured 2026-10-13 on Windows 11 with a Chinese user name and no
# PowerShell 7 installed: a second install of an archive the first had written
# stopped with "not readable as this install's manifest" against the manifest
# that first install had written itself.
# `crates/sure-cli/tests/install_flow.rs`'s
# `the_manifest_round_trips_under_a_non_ascii_user_name` is the case that
# reddens without this flag.
function Read-PreviousManifest {
    param([Parameter(Mandatory)][string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $document = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Stop-Install "there is a file at $Path that is not readable as this install's manifest, so what an earlier install wrote cannot be established. SURE stopped rather than replace files it cannot account for. Move that file aside and run this again."
    }
    if ($document.kind -ne 'sure-install-manifest') {
        Stop-Install "the file at $Path is not a SURE install manifest (kind is '$($document.kind)'), so this directory may hold an install this script did not make. SURE stopped rather than write over it."
    }
    return $document
}

Write-Step 'SURE installer (per-user, Windows)'

# -----------------------------------------------------------------------------
# 1. What was asked for, before anything is written.
# -----------------------------------------------------------------------------
$ArchivePath = [System.IO.Path]::GetFullPath($Archive)
if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
    Stop-Install "there is no archive at $ArchivePath."
}
if ($Checksum -eq '') { $Checksum = "$ArchivePath.sha256" }
$ChecksumPath = [System.IO.Path]::GetFullPath($Checksum)
if (-not (Test-Path -LiteralPath $ChecksumPath -PathType Leaf)) {
    Stop-Install @"
there is no checksum file at $ChecksumPath, so the archive cannot be checked
against anything. SURE will not install bytes it cannot show arrived unchanged.

  A release download carries both files. Build them with:
    & .\scripts\Build-Release.ps1
"@
}

if ($InstallRoot -eq '') {
    $InstallRoot = Join-Path (Get-PerUserDataRoot) 'SURE'
}
$InstallRoot = [System.IO.Path]::GetFullPath($InstallRoot)
if (-not [System.IO.Path]::IsPathRooted($InstallRoot)) {
    Stop-Install "-InstallRoot was given as '$InstallRoot', which is not an absolute path. A relative path would be resolved against whatever directory this ran from."
}

$BinDirectory = Join-Path $InstallRoot 'bin'
$ManifestPath = Join-Path $InstallRoot 'install-manifest.json'
$ArchiveName = [System.IO.Path]::GetFileName($ArchivePath)

Write-Detail "archive      $ArchivePath"
Write-Detail "checksum     $ChecksumPath"
Write-Detail "install to   $BinDirectory"

# -----------------------------------------------------------------------------
# 2. The checksum, checked. This is the property `RELEASE_PROCESS.md` calls an
#    integrity check over the bytes that were shipped, and it is checked here
#    rather than trusted because the point of it is that a second party can
#    check it.
# -----------------------------------------------------------------------------
Write-Step 'Checksum'
$expected = Read-ChecksumLine -Path $ChecksumPath
if ($expected.FileName -ne $ArchiveName) {
    Stop-Install "the checksum file names '$($expected.FileName)' and the archive is '$ArchiveName'. A digest of a different file says nothing about this one."
}
$actual = Get-Sha256 -Path $ArchivePath
if ($actual -ne $expected.Digest) {
    Stop-Install @"
the archive does not match its checksum:

  expected  $($expected.Digest)   ($ChecksumPath)
  actual    $actual              ($ArchivePath)

The bytes are not the bytes that were checked in. Nothing was installed.
"@
}
Write-Detail "sha256       $actual"
Write-Detail 'result       the archive is the file this checksum was written for'

# -----------------------------------------------------------------------------
# 3. Unpack, into a directory of our own, and look at what came out before
#    anything is installed.
# -----------------------------------------------------------------------------
Write-Step 'Unpack'
$scratchRoot = $ScratchDirectory
$createdScratch = $false
if ($scratchRoot -eq '') {
    $scratchRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sure-install-" + [Guid]::NewGuid().ToString('n'))
    $createdScratch = $true
}
$scratchRoot = [System.IO.Path]::GetFullPath($scratchRoot)
$extractDirectory = Join-Path $scratchRoot 'unpacked'

try {
    # A directory this script made is removed whole; one the caller named is only
    # ever touched at its `unpacked` child. `-ScratchDirectory C:\` is a value a
    # person can type, and a recursive delete of the directory they named would
    # be the exact defect this task exists to prevent, one parameter over.
    if ($createdScratch -and (Test-Path -LiteralPath $scratchRoot)) { Remove-Item -LiteralPath $scratchRoot -Recurse -Force }
    if (Test-Path -LiteralPath $extractDirectory) { Remove-Item -LiteralPath $extractDirectory -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $extractDirectory | Out-Null
    Write-Detail "unpacking to $extractDirectory"

    $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($entry in $zip.Entries) {
            Assert-EntryIsInside -EntryName $entry.FullName -Root $extractDirectory
        }
        foreach ($entry in $zip.Entries) {
            $target = [System.IO.Path]::GetFullPath((Join-Path $extractDirectory $entry.FullName))
            $isDirectory = $entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')
            if ($isDirectory) {
                New-Item -ItemType Directory -Force -Path $target | Out-Null
                continue
            }
            $parent = [System.IO.Path]::GetDirectoryName($target)
            if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
    } finally {
        $zip.Dispose()
    }

    # The documented layout is one top-level directory of the archive's own name.
    # Checked rather than assumed: an archive that unpacked differently would
    # otherwise install whatever happened to be called `sure.exe` first.
    $tops = @(Get-ChildItem -LiteralPath $extractDirectory -Force)
    if ($tops.Count -ne 1 -or -not $tops[0].PSIsContainer) {
        Stop-Install "the archive unpacked to $($tops.Count) top-level entries, and the documented layout is one top-level directory. Names found: $(($tops | ForEach-Object { $_.Name }) -join ', ')."
    }
    $topName = $tops[0].Name
    $expectedTop = [System.IO.Path]::GetFileNameWithoutExtension($ArchiveName)
    if ($topName -ne $expectedTop) {
        Stop-Install "the archive's top-level directory is '$topName' and the archive is named '$ArchiveName', so the directory should be '$expectedTop'."
    }

    $payload = @()
    foreach ($name in @('sure.exe', 'LICENSE', 'RELEASE.txt')) {
        $candidate = Join-Path $tops[0].FullName $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $payload += [pscustomobject]@{ Name = $name; Source = $candidate }
        } elseif ($name -eq 'sure.exe') {
            Stop-Install "the archive holds no sure.exe at $candidate, so there is nothing to install."
        }
    }
    Write-Detail "top-level    $topName"
    foreach ($file in $payload) {
        Write-Detail ("payload      {0} ({1} bytes)" -f $file.Name, (Get-Item -LiteralPath $file.Source).Length)
    }

    # -------------------------------------------------------------------------
    # 4. What is already at the destinations.
    #
    # The previous manifest is the only thing that can say a file at one of
    # these paths is this install's. Without that, a file is somebody else's and
    # is left alone unless `-Force` says otherwise — which matters most for the
    # one file in this directory that is definitely not ours to touch, the
    # user's `sure.db`, whose name no destination here ever matches.
    # -------------------------------------------------------------------------
    Write-Step 'Existing files'
    $previous = Read-PreviousManifest -Path $ManifestPath
    $claimed = @{}
    if ($null -ne $previous) {
        foreach ($record in @($previous.files)) {
            $claimed[$record.path.ToLowerInvariant()] = $record.sha256
        }
        Write-Detail "manifest     $ManifestPath (from an earlier install)"
    } else {
        Write-Detail 'manifest     none; no file here is claimed by an earlier install'
    }

    $destinations = @()
    foreach ($file in $payload) {
        $relative = "bin\$($file.Name)"
        $destinations += [pscustomobject]@{ Name = $file.Name; Relative = $relative; Source = $file.Source; Destination = (Join-RelativeTo -Root $InstallRoot -Relative $relative) }
    }

    $obstacles = @()
    $replacing = @()
    foreach ($item in $destinations) {
        if (-not (Test-Path -LiteralPath $item.Destination -PathType Leaf)) { continue }
        $recorded = $claimed[$item.Relative.ToLowerInvariant()]
        if ($null -ne $recorded -and (Get-Sha256 -Path $item.Destination) -eq $recorded) {
            $replacing += $item.Destination
        } else {
            $obstacles += $item.Destination
        }
    }
    if ($obstacles.Count -gt 0 -and -not $Force) {
        Stop-Install @"
these files are already where this install would write, and this install did not
put them there:

$(($obstacles | ForEach-Object { "  $_" }) -join [Environment]::NewLine)

Nothing was installed and nothing was removed. SURE will not replace a file it
cannot account for. If you want it replaced anyway, run this again with -Force,
which names each file it replaces before it does.
"@
    }
    foreach ($path in $obstacles) { Write-Host "   replacing    $path (-Force: this install did not write it)" }
    foreach ($path in $replacing) { Write-Detail "replacing    $path (written by an earlier install of this version)" }

    # -------------------------------------------------------------------------
    # 5. Install. The manifest is written last, so that it never describes a
    #    file that is not there: a manifest that named a missing file would make
    #    the uninstaller report a leak that did not happen.
    # -------------------------------------------------------------------------
    Write-Step 'Install'
    if (-not (Test-Path -LiteralPath $InstallRoot)) {
        New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
        Write-Detail "created      $InstallRoot"
    } else {
        Write-Detail "existing     $InstallRoot (left as it is)"
    }
    if (-not (Test-Path -LiteralPath $BinDirectory)) { New-Item -ItemType Directory -Force -Path $BinDirectory | Out-Null }

    $records = @()
    foreach ($item in $destinations) {
        Copy-Item -LiteralPath $item.Source -Destination $item.Destination -Force
        $bytes = (Get-Item -LiteralPath $item.Destination).Length
        $records += [pscustomobject]@{
            path   = $item.Relative
            sha256 = (Get-Sha256 -Path $item.Destination)
            bytes  = $bytes
        }
        Write-Detail ("installed    {0} ({1} bytes, sha256 {2})" -f $item.Destination, $bytes, $records[-1].sha256)
    }

    # An earlier install's file that this version does not ship is still this
    # install's to remove, and only if it is unchanged. Anything else under
    # `bin\` is left where it is: it is not in the new manifest, so no later
    # uninstall will touch it, which is the correct answer for a file this
    # install did not write.
    $installed = @{}
    foreach ($record in $records) { $installed[$record.path.ToLowerInvariant()] = $true }
    $retired = @()
    foreach ($key in $claimed.Keys) {
        if ($installed.ContainsKey($key)) { continue }
        $path = Join-RelativeTo -Root $InstallRoot -Relative $key
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        if ((Get-Sha256 -Path $path) -ne $claimed[$key]) { continue }
        Remove-Item -LiteralPath $path -Force
        $retired += $path
    }
    foreach ($path in $retired) { Write-Detail "removed      $path (shipped by an earlier install, not by this one)" }

    $manifest = [ordered]@{
        kind         = 'sure-install-manifest'
        schema       = 1
        written_by   = 'scripts/Install-Sure.ps1'
        install_root = $InstallRoot
        installed_at = (Get-Date).ToUniversalTime().ToString('o')
        archive      = $ArchivePath
        archive_sha256 = $actual
        files        = $records
        directories  = @('bin')
    }
    $manifestText = ($manifest | ConvertTo-Json -Depth 6)
    [System.IO.File]::WriteAllText($ManifestPath, $manifestText, [System.Text.UTF8Encoding]::new($false))
    Write-Detail "manifest     $ManifestPath"
} finally {
    if (Test-Path -LiteralPath $extractDirectory) { Remove-Item -LiteralPath $extractDirectory -Recurse -Force -ErrorAction SilentlyContinue }
    if ($createdScratch -and (Test-Path -LiteralPath $scratchRoot)) {
        Remove-Item -LiteralPath $scratchRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------------
# 6. Where the program is, and what was and was not changed to make it reachable.
# -----------------------------------------------------------------------------
Write-Step 'Path and integrations'
$installedExe = Join-Path $BinDirectory 'sure.exe'
$onPath = Get-Command sure -ErrorAction SilentlyContinue
if ($onPath -and $onPath.Source -eq $installedExe) {
    Write-Detail "'sure' on PATH already resolves to $installedExe"
} elseif ($onPath) {
    Write-Host "   'sure' on PATH is $($onPath.Source), which is not this install."
    Write-Host "   This install is at $installedExe. It is reachable by its full path, and by the"
    Write-Host "   eight launcher scripts in this repository, which resolve %LOCALAPPDATA%\SURE\bin\sure.exe"
    Write-Host "   without PATH. To put it on PATH for your own shells, run:"
    Write-Host "     [Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path','User') + ';' + '$BinDirectory'), 'User')"
    Write-Host "   This installer does not run that line: it changes your user environment rather"
    Write-Host "   than this directory, and it is yours to decide."
} else {
    Write-Host "   No 'sure' is on PATH, and none was added: this installer writes no PATH entry,"
    Write-Host "   machine or user. The program is reachable by its full path ($installedExe), and"
    Write-Host "   the launchers in this repository find it without PATH - they resolve"
    Write-Host "   %LOCALAPPDATA%\SURE\bin\sure.exe directly."
    Write-Host "   To put it on PATH for your own shells, run:"
    Write-Host "     [Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path','User') + ';' + '$BinDirectory'), 'User')"
    Write-Host "   This installer does not run that line; docs/development/INSTALL_WINDOWS.md says"
    Write-Host "   what it does and what is not covered by a test."
}

Write-Step 'Done'
Write-Detail "program      $installedExe"
Write-Detail "check it     & '$installedExe' doctor"

# -----------------------------------------------------------------------------
# The signature: read out of the archive's own `RELEASE.txt`, never asserted
# here.
#
# The `signature` line the build wrote into that file is the state the machine
# that built the archive measured, and it is the whole of what anything
# downstream needs to read: the label, then one word. `Get-StatedSignature` is
# the reader, and its text is identical to the one in `scripts/Build-Release.ps1`
# so that the two cannot come to different conclusions about the same file. It
# looks only at the header block, because the prose sections further down are
# full of sentences containing the word "signature".
#
# What is *not* here is a second reading. This script could ask Windows the same
# question about the copy it just installed, and it deliberately does not: that
# would be a second measurer of the same fact, on the machine least able to do
# anything with the answer, and the two could disagree without either being
# wrong. What this script can honestly do is carry the archive's own sentence to
# the person who has just installed it.
#
# When there is no line - an archive built before this existed, or one staged by
# something other than `scripts/Build-Release.ps1` - the answer is that the state
# is not stated. That is `cannot confirm`, and `cannot confirm` is not a yes: it
# is certainly not "unsigned".
# -----------------------------------------------------------------------------
$signatureToken = Get-StatedSignature -Path (Join-Path $BinDirectory 'RELEASE.txt')
switch ($signatureToken) {
    'not-signed' {
        Write-Detail 'signature    not-signed, read from the archive''s own RELEASE.txt and copied to'
        Write-Detail "             $(Join-Path $BinDirectory 'RELEASE.txt')"
        Write-Detail '             the machine that built this archive asked Windows its own question'
        Write-Detail '             about the sure.exe inside it and was told NotSigned, so no'
        Write-Detail '             publisher is named and no certificate signs it.'
        Write-Detail 'warning      Windows may show a SmartScreen or "unknown publisher" prompt the'
        Write-Detail '             first time the program runs. Whether it does is not something this'
        Write-Detail '             project can measure; docs/development/RELEASE_PROCESS.md, "Signing",'
        Write-Detail '             is where that limit and what may not be claimed about it are kept.'
    }
    'signed' {
        Write-Detail 'signature    signed, read from the archive''s own RELEASE.txt'
        Write-Detail '             this is not an archive this project builds: scripts/Build-Release.ps1'
        Write-Detail '             refuses to package a signed binary, because every statement SURE'
        Write-Detail '             publishes says its Windows build carries no signature. This install'
        Write-Detail '             has copied it as it found it and has not verified the signature.'
    }
    'cannot-confirm' {
        Write-Detail 'signature    cannot-confirm, read from the archive''s own RELEASE.txt'
        Write-Detail '             the build that made this archive could not take the reading - the'
        Write-Detail '             cmdlet that answers it is not available in every PowerShell host and'
        Write-Detail '             does not read everything - so it recorded that it did not establish'
        Write-Detail '             the state, and this install repeats that rather than guessing.'
        Write-Detail 'warning      Windows may show a SmartScreen or "unknown publisher" prompt the'
        Write-Detail '             first time the program runs. Whether it does is not something this'
        Write-Detail '             project can measure.'
    }
    default {
        Write-Detail 'signature    not stated: the archive''s RELEASE.txt has no `signature` line in'
        Write-Detail '             its header block, so this install does not know whether the program'
        Write-Detail '             carries an Authenticode signature and does not claim either way.'
        Write-Detail 'warning      Windows may show a SmartScreen or "unknown publisher" prompt the'
        Write-Detail '             first time the program runs.'
    }
}
Write-Detail "uninstall    & '$(Join-Path (Split-Path $PSScriptRoot -Parent) 'scripts\Uninstall-Sure.ps1')' -InstallRoot '$InstallRoot'"
exit 0
