# Block Process

# Part One: Handling the CSV and interacting with it

$csvIntake = Import-CSV -Path ./dailyBlocks.csv

$ipArr = @()
$domainArr = @()
$smtpArr = @()
$legitArr = @()
$intArr = @()
$finalblockList = @()
$potLegitValues = @()

$threshold = 100
$hitCheck = 0

$csvIntake | ForEach-Object {
    $ipArr += $_.IP
    $domainArr += $_.Domains
    $smtpArr += $_.SMTP
}


# Part Two: Performing IOC Scans
$legitDomains = Import-CSV -Path ./legit.csv
$legitDomains | ForEach-Object {
    $legitArr += $_.Domains
}

$interactions = Import-CSV -Path ./interactions.csv
$interactions | ForEach-Object {
    $intArr += $_.Interactions
}

for ($i = 0; $i -lt $domainArr.Length; $i++){

    Write-Host "Scanning Domain : " $domainArr[$i]

    for ($j = 0; $j -lt $legitArr.Length; $j++){

        if ($domainArr[$i] -match $legitArr[$j].Replace('[.]', '\[\.]')){

            Write-Host "LEGIT DOMAIN FOUND | " $domainArr[$i]
            Add-Content -Path LegitDomainIdentified.txt -Value "$($domainArr[$i]) was identified as a legitimate domain/subdomain and was removed from the list."
            continue

        } else {

            for ($k = 0; $k -lt $intArr.Length; $k++){
                if ($domainArr[$i] -match $intArr[$k].Replace('[.]', '\[\.]')){
                    $hitCheck++
                }
            }

            if ($hitCheck -ge $threshold){

                Write-Host "POTENTIALLY LEGIT DOMAIN IDENTIFIED | " $domainArr[$i]
                $potLegitValues += $domainArr[$i]
                Write-Host "Interactions Observed (Count): " $hitCheck
                Add-Content -Path PotentiallyLegitDomain.txt -Value "$($domainArr[$i]) was identified as a potentially legitimate domain. Kindly investigate further"

            } elseif (($hitCheck -gt 0) -AND ($hitCheck -lt $threshold)){
                Write-Host "INTERACTIONS OBSERVED WITH DOMAIN | " $domainArr[$i]
                Write-Host "Interactions Observed (Count): " $hitCheck
                Add-Content -Path InteractionsObservedWithIOC.txt -Value "Interactions were observed with the IOC $($domainArr[$i]). Kindly investigate further" 
                $finalblockList += $domainArr[$i]
            } else {
                $finalblockList += $domainArr[$i]
                Write-Host "Interactions Observed (Count): " $hitCheck
            }

        }
    }
    
    $hitCheck = 0
    Write-Host "---------------------------------------------------"
}

Write-Host "`n`nItems To Be Blocked:"
$finalblockList | ForEach-Object {
    "- $($_)"
}
