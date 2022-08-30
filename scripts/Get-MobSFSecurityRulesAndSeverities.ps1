function Get-LatestMobSFBundle {
    $splat = @{
        Method = 'Get' 
        Uri = 'https://api.github.com/repos/MobSF/mobsfscan/releases/latest'
        ContentType = 'application/json'
    }
    $mobSfLatestVersion = Invoke-RestMethod @splat
    $activeTempRoot = (Get-PSDrive | Where-Object {$_.name -like 'Temp'}).Root

    $oldLocation = (Get-Location).Path
    Set-Location -Path $activeTempRoot
    $splat = @{
        Method = 'Get' 
        Uri = "https://github.com/MobSF/mobsfscan/archive/refs/tags/$($mobSfLatestVersion.tag_name).tar.gz"
        ContentType = 'application/zip'
    }
    Invoke-RestMethod @splat -OutFile "$activeTempRoot/mobSF-$($mobSfLatestVersion.tag_name).tar.gz"
    tar -xzf "mobSF-$($mobSfLatestVersion.tag_name).tar.gz"
    Set-Location -Path $oldLocation
    Get-Item -Path "$activeTempRoot/mobsfscan-$($mobSfLatestVersion.tag_name)"
}

if ((Get-Module).Name -notcontains 'powershell-yaml') {
    Install-Module -Name powershell-yaml
}

$mobSFLocation = Get-LatestMobSFBundle
$ruleFiles = Get-ChildItem -Path "$mobSFLocation/mobsfscan/rules/patterns" -Include "*.yaml" -Recurse -Exclude "*best_practices*"
foreach ($file in $ruleFiles) {
    $rules = Get-Content -Path $file.FullName | ConvertFrom-Yaml -Ordered 
    foreach ($rule in $rules) {
        $ruleObj = [PSCustomObject]@{
            location = ($file.FullName | Select-String -Pattern "mobsfscan.*").Matches.Value
        }

        foreach ($key in $rule.Keys) {
            $ruleObj | Add-Member -MemberType NoteProperty -Name $key -Value $rule."$key" -Force
        }
        $ruleObj | Add-Member -MemberType NoteProperty -Name 'cwe' -Value $ruleObj.metadata.cwe.ToUpper() -Force
        [array]$return += $ruleObj
    }
}

$return | Select-Object -Property id, severity, cwe, location | Export-Csv -Path ./MobSFSecurityRulesAndSeverities.csv -Force
