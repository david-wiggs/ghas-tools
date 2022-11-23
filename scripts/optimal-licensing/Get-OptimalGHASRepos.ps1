[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $False)] [string] $licenseCount
)

function Get-GitHubOrganizationRepositories {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubOrganization
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($gitHubToken)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $page = 0
    do {
        $reposUri = "https://api.github.com/orgs/$gitHubOrganization/repos?page=$page&per_page=100"
        $reposUri = [uri]::EscapeUriString($reposUri)
        $splat = @{
            Method = 'Get' 
            Uri = $reposUri 
            Headers = $headers 
            ContentType = 'application/json'
        }
        [array]$returnRepos = Invoke-RestMethod @splat
        [array]$repositories += $returnRepos
        $page ++
    } until ($returnRepos.Count -lt 100)
    return $repositories
}

function Get-GitHubRepositoryCommits {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $True)] [string] $token,
        [Parameter(Mandatory = $True)] [string] $organization,
        [Parameter(Mandatory = $True)] [string] $repositoryName,
        [Parameter(Mandatory = $False)] [string] $since,
        [Parameter(Mandatory = $False)] [string] $until
    )
    $base64Token = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $headers = @{'Authorization' = "Basic $base64Token"}
    $page = 0
    do {
        if ($PSBoundParameters.ContainsKey('since') -and $PSBoundParameters.ContainsKey('until')) {
            $uri = "https://api.github.com/repos/$organization/$repositoryName/commits?since=$since&until=$until&page=$page&per_page=100"
        } else {
            $uri = "https://api.github.com/repos/$organization/$repositoryName/commits?page=$page&per_page=100"
        }
        $uri = [uri]::EscapeUriString($uri)
        $splat = @{
            Method = 'Get'
            Uri = $uri
            Headers = $headers
            ContentType = 'application/json'
        }
        [array]$return = Invoke-RestMethod @splat
        [array]$commits += $return
        $page ++
    } until ($return.Count -lt 100)
    $commits
}

$splat = @{
    gitHubToken = $gitHubToken
    gitHubOrganization = $gitHubOrganization
}
[array]$orgRepos = Get-GitHubOrganizationRepositories @splat

$since = (Get-date).ToUniversalTime().AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ss")
$until = (Get-date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss")
foreach ($repo in $orgRepos) {
    $splat = @{
        token = $gitHubToken
        organization = $gitHubOrganization
        repositoryName = $repo.name
        since = $since
        until = $until
    }
    try {
        $recentCommits = Get-GitHubRepositoryCommits @splat
    }
    catch {
        if(($_ | ConvertFrom-Json).message -like "Git Repository is empty.") {
            $recentCommits = $null
            Write-Host "Repository $gitHubOrganization/$($repo.name) is empty and does not have any commits."
        } else {
            Write-Error "$_"
        }
    }

    if ($null -ne $recentCommits) {
        [array]$recentCommiters = ($recentCommits.commit.author.email | Select-Object -Unique) 
    } else {
        $recentCommiters = @()
    }
    [array]$report += [PSCustomObject]@{
        organization = $gitHubOrganization
        repository = $repo.name
        recentCommiters = $recentCommiters
    }
}

$report = $report | Where-Object {$_.recentCommiters.Count -gt 0}
$report | ForEach-Object {[array]$values += 1}
$report | ForEach-Object {[array]$weights += $_.recentCommiters.Count}
$pythonText = Get-Content knapsack_template.py
$pythonText = $pythonText.Replace('$values$', ($values -join ', '))
$pythonText = $pythonText.Replace('$weights$', ($weights -join ', '))
$pythonText = $pythonText.Replace('$licenseCount$', $licenseCount)
$pythonText | Out-File optimize.py -Force
$output = python3 optimize.py
$repoIndexies = ($output | Where-Object {$_ -like "Packed items:*"}).split(':')[-1].Replace('[','').Replace(']','').Split(',')

foreach ($index in $repoIndexies) {
    [array]$optimalSet += $report[$index]
}

$optimalSet
