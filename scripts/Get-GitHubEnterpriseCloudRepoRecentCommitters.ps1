[CmdletBinding()]
Param (
    [Parameter(Mandatory = $True)] [string] $gitHubToken,
    [Parameter(Mandatory = $True)] [string] $gitHubOrganization
)
    
function Get-GitHubOrganizationRepositories {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubOrganization
    )
    $headers = @{'Authorization' = "token $gitHubToken"}
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
        [Parameter(Mandatory = $True)] [string] $gitHubToken,
        [Parameter(Mandatory = $True)] [string] $gitHubOrganization,
        [Parameter(Mandatory = $True)] [string] $repositoryName,
        [Parameter(Mandatory = $False)] [string] $since,
        [Parameter(Mandatory = $False)] [string] $until
    )
    $headers = @{'Authorization' = "token $gitHubToken"}
    $page = 0
    do {
        if ($PSBoundParameters.ContainsKey('since') -and $PSBoundParameters.ContainsKey('until')) {
            $uri = "https://api.github.com/repos/$gitHubOrganization/$repositoryName/commits?since=$since&until=$until&page=$page&per_page=100"
        } else {
            $uri = "https://api.github.com/repos/$gitHubOrganization/$repositoryName/commits?page=$page&per_page=100"
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
$orgRepos = Get-GitHubOrganizationRepositories @splat
$since = (Get-date).adddays(-90).ToString("yyyy-MM-ddTHH:mm:ss")
$until = (Get-date).ToString("yyyy-MM-ddTHH:mm:ss")
foreach ($repo in $orgRepos) {
    $recentCommits = $null
    $toAdd = [PSCustomObject]@{repository = $repo.name}
    if ($repo.pushed_at -gt $since) {
        $splat = @{
            gitHubToken = $gitHubToken
            gitHubOrganization = $gitHubOrganization
            repositoryName = $repo.name
            since = $since
            until = $until
        }
        try {
            [array]$recentCommits = Get-GitHubRepositoryCommits @splat
            [array]$recentCommitters = $recentCommits.author.login | Select-Object -Unique
        }
        catch {
            $err = $_ | ConvertFrom-Json
            if ($err.message -like "Git Repository is empty.") {
                $recentCommitters = $null
                $recentCommittersCount = 0
            }
        }
    } 
    
    if ($null -ne $recentCommits) { # Sometimes the recentCommits variable can be null if the most recent push was not on the default branch
        $recentCommittersString = $recentCommitters -join ', '
        $recentCommittersCount = $recentCommitters.Count
    } else {
        $recentCommittersString = $null
        $recentCommittersCount = 0
    }
    $toAdd | Add-Member -MemberType NoteProperty -Name recentCommitters -Value $recentCommittersString
    $toAdd | Add-Member -MemberType NoteProperty -Name recentCommittersCount -Value $recentCommittersCount
    [array]$report += $toAdd
}

$report | Export-Csv github-repos-with-recent-committers.csv -Force
