#Requires -Version 7.0

<#
PREREQUISITES
- PowerShell 7 or later.
- RSAT ActiveDirectory and GroupPolicy modules installed.
- Read access to the Security log on every listed domain controller.
- Run from a machine with WinRM/RPC connectivity to every domain controller in the domain.
#>

# Read-only inventory of GPO permissions and related security events.
Write-Host "[1/4] Loading RSAT modules and discovering the domain..."
if (-not $IsWindows) {
    throw "This audit requires Windows because it uses RSAT and Windows Security event logs."
}

$windowsPowerShellModulePaths = @(
    (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\Modules"),
    (Join-Path $env:WINDIR "SysWOW64\WindowsPowerShell\v1.0\Modules"),
    (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules")
)
$currentModulePaths = @($env:PSModulePath -split [regex]::Escape([string][System.IO.Path]::PathSeparator))
foreach ($modulePath in $windowsPowerShellModulePaths) {
    if ((Test-Path -LiteralPath $modulePath) -and
        -not ($currentModulePaths | Where-Object { $_ -ieq $modulePath })) {
        $env:PSModulePath = @($env:PSModulePath, $modulePath) -join [System.IO.Path]::PathSeparator
        $currentModulePaths += $modulePath
    }
}

$requiredModuleNames = @("ActiveDirectory", "GroupPolicy")
$moduleSearchPaths = @($currentModulePaths + $windowsPowerShellModulePaths)
$moduleSearchPaths = @($moduleSearchPaths | Select-Object -Unique)
$rsatModuleManifestPaths = @{}
foreach ($moduleName in $requiredModuleNames) {
    foreach ($modulePath in $moduleSearchPaths) {
        $manifestPath = Join-Path (Join-Path $modulePath $moduleName) "$moduleName.psd1"
        if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
            $rsatModuleManifestPaths[$moduleName] = $manifestPath
            break
        }
    }
}

$missingModules = @($requiredModuleNames | Where-Object {
    -not $rsatModuleManifestPaths.ContainsKey($_)
})
if ($missingModules.Count -gt 0) {
    throw "RSAT module manifest(s) not found: $($missingModules -join ', '). Searched Windows PowerShell module paths: $($moduleSearchPaths -join '; '). Install the RSAT Active Directory and Group Policy management tools."
}

Import-Module -Name $rsatModuleManifestPaths["ActiveDirectory"] -SkipEditionCheck -ErrorAction Stop
Import-Module -Name $rsatModuleManifestPaths["GroupPolicy"] -SkipEditionCheck -ErrorAction Stop

$domain = Get-ADDomain
$domainController = $domain.PDCEmulator
$domainDnsRoot = $domain.DNSRoot
$domainDn = $domain.DistinguishedName
Write-Host "[2/4] Discovering domain controllers via $domainController..."
$domainControllers = Get-ADDomainController -Filter * -Server $domainController |
    Select-Object -ExpandProperty HostName
$since = (Get-Date).AddDays(-30)
$collectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$reportPath = Join-Path $PWD "gpo-sysvol-audit-$runId.csv"
$records = [System.Collections.Generic.List[object]]::new()
$principalKeyCache = [System.Collections.Concurrent.ConcurrentDictionary[string, string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

Write-Host "[3/4] Enumerating GPOs from $domainController..."
$gpos = @(Get-GPO -All -Domain $domain.DNSRoot -Server $domainController)
$groupPolicyModuleManifestPath = $rsatModuleManifestPaths["GroupPolicy"]
Write-Host "Found $($gpos.Count) GPOs; reading their GPC and GPT ACLs..."
$gpcByDn = @{}
$gpoByGuid = @{}

foreach ($gpo in $gpos) {
    $gpoGuid = $gpo.Id.ToString("B")
    $gpcDn = "CN=$gpoGuid,CN=Policies,CN=System,$($domain.DistinguishedName)"
    $gpcByDn[$gpcDn] = $gpo
    $gpoByGuid[$gpo.Id.ToString("D")] = $gpo
    $gpoByGuid[$gpoGuid] = $gpo
}

# Each worker returns its own ACL rows; the shared report list is only updated after the parallel loop.
$gpoWork = for ($index = 0; $index -lt $gpos.Count; $index++) {
    [pscustomobject]@{
        Index = $index + 1
        Total = $gpos.Count
        GpoId = $gpos[$index].Id
        GpoDisplayName = [string]$gpos[$index].DisplayName
    }
}

$gpoRows = @($gpoWork | ForEach-Object -Parallel {
    $workItem = $_
    $gpoId = $workItem.GpoId
    $gpoDisplayName = $workItem.GpoDisplayName
    $domainController = $using:domainController
    $domainDnsRoot = $using:domainDnsRoot
    $domainDn = $using:domainDn
    $collectedAtUtc = $using:collectedAtUtc
    $principalKeyCache = $using:principalKeyCache
    $groupPolicyModuleManifestPath = $using:groupPolicyModuleManifestPath
    $gpoRecords = [System.Collections.Generic.List[object]]::new()
    $progressId = $workItem.Index

    function Get-PrincipalKey {
        param([object]$Principal, [object]$Cache)

        if ($Principal -is [System.Security.Principal.SecurityIdentifier]) {
            return $Principal.Value
        }

        $sidProperty = $Principal.PSObject.Properties["Sid"]
        if ($sidProperty -and $sidProperty.Value) {
            if ($sidProperty.Value -is [System.Security.Principal.SecurityIdentifier]) {
                return $sidProperty.Value.Value
            }
            if ([string]$sidProperty.Value -match '^S-\d-') {
                return ([System.Security.Principal.SecurityIdentifier]::new([string]$sidProperty.Value)).Value
            }
        }

        $principalText = if ($Principal -is [System.Security.Principal.IdentityReference]) {
            $Principal.Value
        }
        else {
            [string]$Principal
        }
        $cachedKey = $null
        if ($Cache.TryGetValue($principalText, [ref]$cachedKey)) {
            return $cachedKey
        }

        try {
            if ($Principal -is [System.Security.Principal.IdentityReference]) {
                $identity = $Principal
            }
            else {
                $identity = [System.Security.Principal.NTAccount]::new($principalText)
            }

            $principalKey = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            $principalKey = $principalText.Trim().ToUpperInvariant()
        }

        [void]$Cache.TryAdd($principalText, $principalKey)
        return $principalKey
    }

    function Get-PrincipalName {
        param([object]$Principal)

        $nameProperty = $Principal.PSObject.Properties["Name"]
        $domainProperty = $Principal.PSObject.Properties["Domain"]
        if ($nameProperty) {
            if ($domainProperty -and $domainProperty.Value) {
                return "{0}\{1}" -f $domainProperty.Value, $nameProperty.Value
            }
            return [string]$nameProperty.Value
        }

        return [string]$Principal
    }

    Write-Progress -Id $progressId -Activity "Reading GPO ACLs" `
        -Status "$($workItem.Index)/$($workItem.Total): $gpoDisplayName" -PercentComplete 5

    try {
        Import-Module -Name $groupPolicyModuleManifestPath -SkipEditionCheck -ErrorAction Stop
        $gpoGuid = $gpoId.ToString("B")
        $gpcDn = "CN=$gpoGuid,CN=Policies,CN=System,$domainDn"
        $gptPath = "\\$domainController\SYSVOL\$domainDnsRoot\Policies\$gpoGuid"

        try {
            $gpoPermissions = @(Get-GPPermission -Guid $gpoId -All `
                -DomainName $domainDnsRoot -Server $domainController -ErrorAction Stop)
            Write-Progress -Id $progressId -Activity "Reading GPO ACLs" `
                -Status "$($workItem.Index)/$($workItem.Total): reading SYSVOL ACL for $gpoDisplayName" -PercentComplete 45
            $gptAcl = Get-Acl -LiteralPath $gptPath -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not read GPO '$gpoDisplayName' or GPT '$gptPath': $($_.Exception.Message)"
            return
        }

        $gpcPrincipalKeys = @{}
        foreach ($permission in $gpoPermissions) {
            $principalKey = Get-PrincipalKey $permission.Trustee $principalKeyCache
            $gpcPrincipalKeys[$principalKey] = $true
        }

        $gptPrincipalKeys = @{}
        foreach ($ace in $gptAcl.Access) {
            $principalKey = Get-PrincipalKey $ace.IdentityReference $principalKeyCache
            $gptPrincipalKeys[$principalKey] = $true
        }

        foreach ($permission in $gpoPermissions) {
            $principalKey = Get-PrincipalKey $permission.Trustee $principalKeyCache
            $permissionProperty = $permission.PSObject.Properties["Permission"]
            if (-not $permissionProperty) {
                $permissionProperty = $permission.PSObject.Properties["PermissionLevel"]
            }
            $permissionLevel = if ($permissionProperty) { [string]$permissionProperty.Value } else { "Review GPPermission object" }
            $counterpart = if ($gptPrincipalKeys.ContainsKey($principalKey)) {
                "Trustee present on both ACLs; compare permissions"
            }
            else {
                "Trustee only in GPC; review"
            }

            [void]$gpoRecords.Add([pscustomobject]@{
                CollectedAtUtc = $collectedAtUtc
                RecordType = "ACL snapshot"
                DomainController = $domainController
                GpoDisplayName = $gpoDisplayName
                GpoGuid = $gpoId
                GpcDistinguishedName = $gpcDn
                GptPath = $gptPath
                Source = "GPC / Get-GPPermission"
                Principal = Get-PrincipalName $permission.Trustee
                PrincipalKey = $principalKey
                Permission = $permissionLevel
                AccessControlType = ""
                IsInherited = [string]$permission.Inherited
                InheritanceProtected = ""
                ComparisonSignal = $counterpart
                EventId = ""
                EventTimeUtc = ""
                Actor = ""
                Attribute = ""
                Value = ""
                OperationType = ""
                CorrelationId = ""
                RecordId = ""
                AccessMask = ""
                ProcessName = ""
                OldSecurityDescriptor = ""
                NewSecurityDescriptor = ""
            })
        }

        foreach ($ace in $gptAcl.Access) {
            $principalKey = Get-PrincipalKey $ace.IdentityReference $principalKeyCache
            $principalSignal = if ($gpcPrincipalKeys.ContainsKey($principalKey)) {
                "Trustee present on both ACLs; compare permissions"
            }
            else {
                "Trustee only in GPT; review"
            }
            $inheritanceSignal = if ($gptAcl.AreAccessRulesProtected) {
                "GPT DACL protected from parent inheritance"
            }
            else {
                "GPT DACL inherits from parent; review GPMC consistency"
            }

            [void]$gpoRecords.Add([pscustomobject]@{
                CollectedAtUtc = $collectedAtUtc
                RecordType = "ACL snapshot"
                DomainController = $domainController
                GpoDisplayName = $gpoDisplayName
                GpoGuid = $gpoId
                GpcDistinguishedName = $gpcDn
                GptPath = $gptPath
                Source = "GPT / SYSVOL NTFS"
                Principal = $ace.IdentityReference.Value
                PrincipalKey = $principalKey
                Permission = [string]$ace.FileSystemRights
                AccessControlType = [string]$ace.AccessControlType
                IsInherited = [string]$ace.IsInherited
                InheritanceProtected = [string]$gptAcl.AreAccessRulesProtected
                ComparisonSignal = "$principalSignal; $inheritanceSignal"
                EventId = ""
                EventTimeUtc = ""
                Actor = ""
                Attribute = ""
                Value = ""
                OperationType = ""
                CorrelationId = ""
                RecordId = ""
                AccessMask = ""
                ProcessName = ""
                OldSecurityDescriptor = ""
                NewSecurityDescriptor = ""
            })
        }
    }
    finally {
        Write-Progress -Id $progressId -Activity "Reading GPO ACLs" -Completed
    }

    foreach ($record in $gpoRecords) {
        $record
    }
} -ThrottleLimit 5)
$records.AddRange([object[]]$gpoRows)
Write-Progress -Activity "Reading GPO ACLs" -Completed

Write-Host "[4/4] Reading recent Security events from all domain controllers..."
$eventIds = @(4670, 5136)
$objectTypeGuid = "f30e3bc2-9ff0-11d1-b603-0000f80367c1"
$sinceUtc = $since.ToUniversalTime().ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ",
    [System.Globalization.CultureInfo]::InvariantCulture
)
$event4662XPath = "*[System[(EventID=4662) and TimeCreated[@SystemTime >= '$sinceUtc']] and EventData[Data[@Name='ObjectType']='%{$objectTypeGuid}' or Data[@Name='ObjectType']='{$objectTypeGuid}' or Data[@Name='ObjectType']='$objectTypeGuid']]"
$dcWork = for ($index = 0; $index -lt $domainControllers.Count; $index++) {
    [pscustomobject]@{
        Index = $index + 1
        Total = $domainControllers.Count
        HostName = $domainControllers[$index]
    }
}
$eventIdsForWorkers = $eventIds

# 4662 ObjectType identifies groupPolicyContainer; the XPath matches common raw GUID encodings.
# If a DC uses another encoding, replace this query with the broader FilterHashtable fallback below.
# Get-WinEvent -ComputerName $eventDc -FilterHashtable @{
#     LogName = "Security"
#     Id = 4662
#     StartTime = $since
# } -ErrorAction Stop
# The WRITE_DAC AccessMask check remains client-side.
$eventRows = @($dcWork | ForEach-Object -Parallel {
    $workItem = $_
    $eventDc = $workItem.HostName
    $domainController = $using:domainController
    $domainDnsRoot = $using:domainDnsRoot
    $domainDn = $using:domainDn
    $gpcByDn = $using:gpcByDn
    $gpoByGuid = $using:gpoByGuid
    $collectedAtUtc = $using:collectedAtUtc
    $since = $using:since
    $event4662XPath = $using:event4662XPath
    $eventRecords = [System.Collections.Generic.List[object]]::new()
    $eventCount = 0
    $progressId = 1000 + $workItem.Index

    Write-Progress -Id $progressId -Activity "Reading Security events" `
        -Status "$($workItem.Index)/$($workItem.Total): querying $eventDc" -PercentComplete 5

    try {
        $events = [System.Collections.Generic.List[object]]::new()
        try {
            $filtered4662 = @(Get-WinEvent -ComputerName $eventDc -LogName "Security" `
                -FilterXPath $event4662XPath -ErrorAction Stop)
            $events.AddRange([object[]]$filtered4662)
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike "NoMatchingEventsFound,*") {
                Write-Warning "Could not read event 4662 from '$eventDc': $($_.Exception.Message)"
            }
        }
        Write-Progress -Id $progressId -Activity "Reading Security events" `
            -Status "$eventDc`: 4662 query complete; reading 4670/5136" -PercentComplete 40

        try {
            $filteredOtherEvents = @(Get-WinEvent -ComputerName $eventDc -FilterHashtable @{
                LogName = "Security"
                Id = $using:eventIdsForWorkers
                StartTime = $since
            } -ErrorAction Stop)
            $events.AddRange([object[]]$filteredOtherEvents)
        }
        catch {
            if ($_.FullyQualifiedErrorId -notlike "NoMatchingEventsFound,*") {
                Write-Warning "Could not read Security events 4670/5136 from '$eventDc': $($_.Exception.Message)"
            }
        }
        $totalEvents = $events.Count
        Write-Progress -Id $progressId -Activity "Reading Security events" `
            -Status "$eventDc`: processing $totalEvents candidate events" -PercentComplete 60

        foreach ($event in $events) {
            $eventCount++
            if ($eventCount -eq 1 -or $eventCount % 500 -eq 0) {
                $eventPercentComplete = if ($totalEvents) {
                    60 + [int](40 * $eventCount / $totalEvents)
                }
                else {
                    100
                }
                Write-Progress -Id $progressId -Activity "Reading Security events" `
                    -Status "$eventDc`: processed $eventCount candidate events" `
                    -CurrentOperation "Matching events to GPOs and building report" `
                    -PercentComplete $eventPercentComplete
            }

            [xml]$eventXml = $event.ToXml()
            $eventData = @{}
            foreach ($field in $eventXml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")) {
                $eventData[$field.GetAttribute("Name")] = $field.InnerText
            }

            $objectName = if ($event.Id -eq 5136) { $eventData["ObjectDN"] } else { $eventData["ObjectName"] }
            $matchedGpo = $null

            if ($objectName -and $gpcByDn.ContainsKey($objectName)) {
                $matchedGpo = $gpcByDn[$objectName]
            }
            elseif ($objectName) {
                $guidMatch = [regex]::Match(
                    [string]$objectName,
                    '(?i)\{?(?<Guid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?'
                )
                if ($guidMatch.Success) {
                    $normalizedGuid = ([guid]::Parse($guidMatch.Groups["Guid"].Value)).ToString("D")
                    $matchedGpo = $gpoByGuid[$normalizedGuid]
                }
            }

            if (-not $matchedGpo) { continue }

            if ($event.Id -eq 4662) {
                $maskText = ([string]$eventData["AccessMask"]) -replace '^0x', ''
                [uint32]$accessMask = 0
                $parsedMask = [uint32]::TryParse(
                    $maskText,
                    [System.Globalization.NumberStyles]::HexNumber,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref]$accessMask
                )
                if (-not $parsedMask -or ($accessMask -band 0x40000) -eq 0) { continue }
            }

            $matchedGuid = $matchedGpo.Id.ToString("B")
            $matchedDn = "CN=$matchedGuid,CN=Policies,CN=System,$domainDn"
            $matchedGptPath = "\\$domainController\SYSVOL\$domainDnsRoot\Policies\$matchedGuid"
            $actor = "{0}\{1}" -f $eventData["SubjectDomainName"], $eventData["SubjectUserName"]

            [void]$eventRecords.Add([pscustomobject]@{
                CollectedAtUtc = $collectedAtUtc
                RecordType = "Security event"
                DomainController = $eventDc
                GpoDisplayName = $matchedGpo.DisplayName
                GpoGuid = $matchedGpo.Id
                GpcDistinguishedName = $matchedDn
                GptPath = $matchedGptPath
                Source = "Windows Security"
                Principal = ""
                PrincipalKey = ""
                Permission = ""
                AccessControlType = ""
                IsInherited = ""
                InheritanceProtected = ""
                ComparisonSignal = ""
                EventId = $event.Id
                EventTimeUtc = $event.TimeCreated.ToUniversalTime().ToString("o")
                Actor = $actor
                Attribute = $eventData["AttributeLDAPDisplayName"]
                Value = $eventData["AttributeValue"]
                OperationType = $eventData["OperationType"]
                CorrelationId = $eventData["OpCorrelationID"]
                RecordId = $event.RecordId
                AccessMask = $eventData["AccessMask"]
                ProcessName = $eventData["ProcessName"]
                OldSecurityDescriptor = $eventData["OldSd"]
                NewSecurityDescriptor = $eventData["NewSd"]
            })
        }
    }
    finally {
        Write-Progress -Id $progressId -Activity "Reading Security events" -Completed
    }

    foreach ($record in $eventRecords) {
        $record
    }
} -ThrottleLimit 3)
$records.AddRange([object[]]$eventRows)
Write-Progress -Activity "Reading Security events" -Completed
# Preserve the CSV export and add an offline HTML companion from the same collected rows.
Write-Host "Exporting $($records.Count) report rows to $reportPath..."
$records | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
Write-Host "Building the interactive HTML report..."
$htmlReportPath = [System.IO.Path]::ChangeExtension($reportPath, ".html")
$reportJson = ConvertTo-Json -InputObject @($records.ToArray()) -Depth 4 -Compress
$reportJson = $reportJson.Replace("&", '\u0026').Replace("<", '\u003c').Replace(">", '\u003e')
$csvFileName = [System.IO.Path]::GetFileName($reportPath)

$htmlTemplate = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GPO / SYSVOL Audit</title>
<style>
:root{color-scheme:light;--ink:#17242b;--muted:#52646d;--line:#d4dee1;--paper:#f4f7f5;--panel:#fff;--teal:#087f78;--blue:#356e91;--amber:#a85b08;--red:#a63232;font-family:Segoe UI,Arial,sans-serif}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink)}header{background:#173940;color:#f7fbfa;padding:28px max(24px,calc((100vw - 1320px)/2)) 24px}header h1{font-size:25px;margin:0 0 8px}header p{margin:0;color:#d2e0df}main{max-width:1320px;margin:24px auto;padding:0 24px 48px}.notice{border-left:4px solid var(--amber);background:#fff7e8;color:#57370f;padding:12px 16px;margin:0 0 20px}.meta{display:flex;flex-wrap:wrap;gap:8px 22px;color:var(--muted);font-size:13px;margin:0 0 20px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:20px}.metric,.panel{background:var(--panel);border:1px solid var(--line);border-radius:5px}.metric{padding:16px}.metric span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase}.metric strong{display:block;font-size:25px;margin-top:7px}.metric.review strong{color:var(--amber)}.charts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:20px}.panel{padding:16px;min-width:0}.panel h2{font-size:15px;margin:0 0 16px}.bars{display:grid;gap:10px}.bar-row{display:grid;grid-template-columns:minmax(70px,110px) 1fr 36px;align-items:center;gap:8px;font-size:12px}.bar-label{overflow-wrap:anywhere;color:var(--muted)}.bar-track{height:12px;background:#e8eeee;border-radius:2px;overflow:hidden}.bar-fill{display:block;height:100%;background:var(--teal);min-width:2px}.bar-value{text-align:right;font-variant-numeric:tabular-nums}.empty{color:var(--muted);font-size:13px}.table-panel h2{margin-bottom:12px}.toolbar{display:flex;gap:10px;margin-bottom:12px}.toolbar input,.toolbar select{height:38px;border:1px solid #aebdc2;background:white;color:var(--ink);border-radius:3px;padding:0 10px;font:inherit}.toolbar input{flex:1;min-width:140px}.toolbar select{min-width:170px}.table-wrap{overflow:auto;border:1px solid var(--line);max-height:65vh;background:white}table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid #e5ebed;max-width:300px;overflow-wrap:anywhere}th{position:sticky;top:0;background:#eaf0f0;z-index:1;color:#30444b;font-size:11px;text-transform:uppercase}tbody tr:hover{background:#f1f8f6}.signal{color:var(--amber)}.pager{display:flex;align-items:center;justify-content:flex-end;gap:10px;padding-top:12px;font-size:13px;color:var(--muted)}button{border:1px solid #9eafb4;background:white;color:var(--ink);border-radius:3px;padding:7px 12px;cursor:pointer}button:hover:not(:disabled){border-color:var(--teal);color:var(--teal)}button:disabled{opacity:.45;cursor:default}a{color:#b9e4dc}footer{color:var(--muted);font-size:12px;margin-top:14px}@media(max-width:900px){.charts{grid-template-columns:1fr 1fr}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:560px){header{padding:22px 18px}main{padding:0 14px 32px;margin-top:16px}.charts{grid-template-columns:1fr}.metrics{gap:8px}.metric{padding:12px}.metric strong{font-size:22px}.toolbar{flex-direction:column}.toolbar select{width:100%}.bar-row{grid-template-columns:minmax(65px,95px) 1fr 30px}}
</style>
</head>
<body>
<header><h1>GPO / SYSVOL Audit</h1><p>Read-only ACL snapshot and recent security event review</p></header>
<main>
<p class="notice">Internal security report: contains domain, controller, policy, and identity data. Store and share it as sensitive.</p>
<p class="notice">Unmatched trustees are triage signals, not confirmed vulnerabilities. Check nested group membership, effective NTFS and Share rights, ACE inheritance scope, and GPMC before remediation.</p>
<p class="meta"><span>Domain: __DOMAIN__</span><span>Snapshot DC: __PDC__</span><span>Collected: __COLLECTED_AT__</span><a href="__CSV_FILE__">Download full CSV</a></p>
<section class="metrics" aria-label="Summary">
<div class="metric"><span>GPOs scanned</span><strong id="gpo-count">__GPO_COUNT__</strong></div>
<div class="metric"><span>ACL snapshot rows</span><strong id="acl-count">0</strong></div>
<div class="metric"><span>Matched security events</span><strong id="event-count">0</strong></div>
<div class="metric review"><span>ACL rows with unmatched trustees</span><strong id="unmatched-count">0</strong></div>
</section>
<section class="charts" aria-label="Event and source charts">
<article class="panel"><h2>Security events by ID</h2><div class="bars" id="event-chart"></div></article>
<article class="panel"><h2>ACL rows by source</h2><div class="bars" id="source-chart"></div></article>
<article class="panel"><h2>Matched events by controller</h2><div class="bars" id="dc-chart"></div></article>
</section>
<section class="panel table-panel">
<h2>Report records</h2>
<div class="toolbar"><input id="search" type="search" placeholder="Search report records" aria-label="Search report records"><select id="record-type" aria-label="Filter by record type"><option value="">All record types</option></select></div>
<div class="table-wrap"><table><thead><tr><th>Time</th><th>Type</th><th>Controller</th><th>GPO</th><th>Source</th><th>Principal</th><th>Permission</th><th>Event</th><th>Actor</th><th>Review signal</th></tr></thead><tbody id="records"></tbody></table></div>
<div class="pager"><span id="page-label"></span><button id="previous" type="button">Previous</button><button id="next" type="button">Next</button></div>
</section>
<footer>Charts and filters run locally in this file. No data is sent over the network.</footer>
</main>
<script id="report-data" type="application/json">__REPORT_DATA__</script>
<script>
"use strict";
const rows=JSON.parse(document.getElementById("report-data").textContent);
const aclRows=rows.filter(row=>row.RecordType==="ACL snapshot");
const eventRows=rows.filter(row=>row.RecordType==="Security event");
const unmatchedRows=aclRows.filter(row=>/Trustee only in (GPC|GPT)/i.test(String(row.ComparisonSignal||"")));
document.getElementById("acl-count").textContent=String(aclRows.length);
document.getElementById("event-count").textContent=String(eventRows.length);
document.getElementById("unmatched-count").textContent=String(unmatchedRows.length);
function tally(items,key){const counts=new Map();for(const item of items){const label=String(key(item)||"Unspecified");counts.set(label,(counts.get(label)||0)+1)}return Array.from(counts.entries()).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]))}
function renderBars(targetId,entries){const target=document.getElementById(targetId);target.replaceChildren();if(!entries.length){const empty=document.createElement("p");empty.className="empty";empty.textContent="No matching records";target.append(empty);return}const max=Math.max(...entries.map(entry=>entry[1]),1);for(const [label,count] of entries){const row=document.createElement("div");row.className="bar-row";const name=document.createElement("span");name.className="bar-label";name.textContent=label;const track=document.createElement("span");track.className="bar-track";const fill=document.createElement("span");fill.className="bar-fill";fill.style.width=`${Math.max(2,100*count/max)}%`;track.append(fill);const value=document.createElement("span");value.className="bar-value";value.textContent=String(count);row.append(name,track,value);target.append(row)}}
renderBars("event-chart",tally(eventRows,row=>row.EventId));
renderBars("source-chart",tally(aclRows,row=>row.Source));
renderBars("dc-chart",tally(eventRows,row=>row.DomainController));
const typeSelect=document.getElementById("record-type");for(const type of Array.from(new Set(rows.map(row=>row.RecordType))).sort()){const option=document.createElement("option");option.value=type;option.textContent=type;typeSelect.append(option)}
const columns=["CollectedAtUtc","RecordType","DomainController","GpoDisplayName","Source","Principal","Permission","EventId","Actor","ComparisonSignal"];
const search=document.getElementById("search");const body=document.getElementById("records");const pageLabel=document.getElementById("page-label");const previous=document.getElementById("previous");const next=document.getElementById("next");const pageSize=100;let page=0;
function renderTable(){const term=search.value.trim().toLocaleLowerCase();const type=typeSelect.value;const filtered=rows.filter(row=>(!type||row.RecordType===type)&&(!term||Object.values(row).some(value=>String(value??"").toLocaleLowerCase().includes(term))));const pageCount=Math.max(1,Math.ceil(filtered.length/pageSize));page=Math.min(page,pageCount-1);body.replaceChildren();for(const item of filtered.slice(page*pageSize,(page+1)*pageSize)){const tr=document.createElement("tr");for(const column of columns){const td=document.createElement("td");td.textContent=String(item[column]??"");if(column==="ComparisonSignal"&&/review/i.test(td.textContent))td.className="signal";tr.append(td)}body.append(tr)}pageLabel.textContent=filtered.length?`${page*pageSize+1}-${Math.min((page+1)*pageSize,filtered.length)} of ${filtered.length}`:"0 records";previous.disabled=page===0;next.disabled=(page+1)*pageSize>=filtered.length}
search.addEventListener("input",()=>{page=0;renderTable()});typeSelect.addEventListener("change",()=>{page=0;renderTable()});previous.addEventListener("click",()=>{page=Math.max(0,page-1);renderTable()});next.addEventListener("click",()=>{page++;renderTable()});renderTable();
</script>
</body>
</html>
'@
$htmlReport = $htmlTemplate.Replace("__DOMAIN__", [System.Net.WebUtility]::HtmlEncode($domainDnsRoot))
$htmlReport = $htmlReport.Replace("__PDC__", [System.Net.WebUtility]::HtmlEncode($domainController))
$htmlReport = $htmlReport.Replace("__COLLECTED_AT__", [System.Net.WebUtility]::HtmlEncode($collectedAtUtc))
$htmlReport = $htmlReport.Replace("__CSV_FILE__", [System.Net.WebUtility]::HtmlEncode($csvFileName))
$htmlReport = $htmlReport.Replace("__GPO_COUNT__", [string]$gpos.Count)
$htmlReport = $htmlReport.Replace("__REPORT_DATA__", $reportJson)
[System.IO.File]::WriteAllText($htmlReportPath, $htmlReport, [System.Text.UTF8Encoding]::new($false))

Write-Host "CSV report written to $reportPath ($($records.Count) rows)"
Write-Host "Interactive HTML report written to $htmlReportPath"
