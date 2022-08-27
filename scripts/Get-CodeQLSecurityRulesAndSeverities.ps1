function Get-GitHubRepositoryFileContent {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubRepository,
        [Parameter(Mandatory = $True)] [string] $path,
        [Parameter(Mandatory = $True)] [string] $branch,
        [Parameter(Mandatory = $False)] [string] $token
    )
    $uri = "https://api.github.com/repos/$gitHubRepository/contents/$path`?ref=$branch" # Need to escape the ? that indicates an http query
    $uri = [uri]::EscapeUriString($uri)
    $splat = @{
        Method = 'Get'
        Uri = $uri
        Headers = $headers
        ContentType = 'application/json'
    }
    if ($PSBoundParameters.ContainsKey('token')) {
        $headers = @{'Authorization' = "token $token"}
        $splat.Add('Headers', $headers)
    } 
    
    try {
        $fileData = Invoke-RestMethod @splat
        [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($fileData.content)) | Out-File -FilePath $(Split-Path $path -Leaf) -Force
        Get-Item -Path $(Split-Path $path -Leaf)
    } catch {
        Write-Warning "Unable to get file content."   
        $ErrorMessage = $_.Exception.Message
        Write-Warning "$ErrorMessage"
        break
    }
}

function Get-DotSourceFileFromGitHub {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $gitHubRepository,
        [Parameter(Mandatory = $True)] [string] $path,
        [Parameter(Mandatory = $True)] [string] $branch,
        [Parameter(Mandatory = $False)] [string] $token
    )
    
    $splat = @{
        gitHubRepository = $gitHubRepository
        path = $path
        branch = $branch
    }
    if ($PSBoundParameters.ContainsKey('token')) {$splat.Add('token', $token)}
    $dotSourcefile = Get-GitHubRepositoryFileContent @splat 
    $content = Get-Content -Path $dotSourcefile.FullName 
    $content.Replace('function ', 'function Global:') | Out-File $dotSourceFile.FullName -Force
    . $dotSourcefile.FullName
    Remove-Item -Path $dotSourcefile.FullName -Force
}

$splat = @{
    gitHubRepository = 'david-wiggs/codeql-anywhere'
    path = 'resources/functions.ps1'
    branch = 'main'
}
Get-DotSourceFileFromGitHub @splat

$codeQLDirectory = Get-LatestCodeQLBundle
$qlFiles = Get-ChildItem -Recurse -Path $codeQLDirectory -Include "*.ql" 
foreach ($file in $qlFiles) {
    $content = Get-Content -Path $file.FullName
    if ($null -ne ($content | Select-String -Pattern '\* @security-severity')) {
        $data = ($content | Select-String -Pattern '\* @') | ForEach-Object {$_.ToString()} | ForEach-Object {$_.Replace('* @', '') | ForEach-Object {$_.Trim()}}
        if ($null -ne ($data | Where-Object {$_ -like 'precision*'})) {
            $precision = ($data | Where-Object {$_ -like "precision*"}).Split()[-1]
        } else {
            $precision = 'N/A'
        }

        if ($file.FullName -like "*cwe*") {
            $cwe = ($file.FullName | Select-String -Pattern 'cwe-\d{3,4}').Matches.Value.ToUpper()
        } else {
            $cwe = 'N/A'
        }

        [int]$securitySeverity = ($data | Where-Object {$_ -like "security-severity*"}).Split()[-1] 
        if ($securitySeverity -ge 9) {
            $severity = 'critical'
        } elseif ($securitySeverity -ge 7 -and $securitySeverity -lt 9 ) {
            $severity = 'high'
        } elseif ($securitySeverity -ge 4 -and $securitySeverity -lt 7 ) {
            $severity = 'medium'
        } elseif ($securitySeverity -gt 0 -and $securitySeverity -lt 4 ) {
            $severity = 'low'
        } 

        $dataObj = [PSCustomObject]@{
            name = ($data | Where-Object {$_ -like "name*"}).Split() | Where-Object {$_ -notlike 'name'} | Join-String -Separator ' '
            'security-severity' = $securitySeverity
            severity = $severity
            precision = $precision
            id = ($data | Where-Object {$_ -like "id*"}).Split()[-1]
            language = ($data | Where-Object {$_ -like "id*"}).Split()[-1].Split('/')[0]
            location = ($file.FullName | Select-String -Pattern 'codeql.*').Matches.Value
            cwe = $cwe
        }
        [array]$report += $dataObj
    }
}
$report | Export-Csv -Path CodeQLSecuritySeverityRules.csv -Force