param (   
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Alert','AlertAndBlock','Allowed')]   #Validate that the input contains valid value
    [string]$action = 'Alert',                         #Set default action to 'Alert'
    
    [Parameter(Mandatory=$true)]
    [string]$title, 
   
    [Parameter(Mandatory=$false)]
    [ValidateSet('Informational','Low','Medium','High')]   #Validate that the input contains valid value
    [string]$severity = 'Informational',                   #Set default severity to 'informational'
    
    [Parameter(Mandatory=$false)]
    [string]$description,     

    [Parameter(Mandatory=$false)]
    [string]$recommendedActions,     

    [Parameter(Mandatory=$true)]
    [string]$authKey, 
    
    [Parameter(Mandatory=$true)]
    [string]$mispUrl,

    [Parameter(Mandatory=$false)]
    [string]$expiration = 7                                #Set default expiration to 7 days
     
 )

$token = ./Get-Token.ps1                                   #Execute Get-Token.ps1 script to get the authorization token

#Call MISP API and save result to JSON_DATE.txt
$authorization = "Authorization: " + $authKey
$response = curl -k --header $authorization --header "Accept: application/json" --header "Content-Type: application/json" https://$mispUrl/events/hids/sha1/download/false/false/false/4d > JSON_DATE.txt

if($response.StatusCode -ne 200)                           #Check the response status code
{
    
    return $false                                          #MISP call failed
}

#Build and call the MDATP indicators API with the data from MISP
$url = "https://api.securitycenter.windows.com/api/indicators"     

$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}

[datetime]$datetimeOffsetTest = [DateTime]::Now.AddDays($expiration)

$arrayOfIndicators = @(Get-Content JSON_DATE.txt | Where-Object { $_.Trim() -ne '' } )
Foreach($indicator in $arrayOfIndicators){                                                    #Call Microsoft Defender ATP API for each hash
    if(!($indicator.Startswith("#"))){                                                        #Ignore comments on start of file
        $body = 
        @{
	        indicatorValue = ($indicator|out-string).Trim()    
            indicatorType = "FileSha1"
            expirationTime = $datetimeOffsetTest |  get-date -Format "yyyy-MM-ddTHH:mm:ssZ" 
            action = $action
            title = $title 
            severity = $severity	
            description = $description 
            recommendedActions = $recommendedActios 
        }

        $response = try { 
            (Invoke-WebRequest -Method Post -Uri $url -Body ($body | ConvertTo-Json) -Headers $headers -ErrorAction Stop).BaseResponse
        } catch [System.Net.WebException] { 
            $_.Exception.Response 
        }

        if($response.StatusCode -ne 200)                                              #Check the response status code
        {
            if($response.StatusCode -eq 409)
            {
                Write-Output("Indicator " + $indicator + " has a conflict")           #If the indicatorValue is already in your Microsoft Defender ATP list with a different "action" field, it won't be submitted
            }
            else
            {
                Write-Output("Indicator " + $indicator + " failed to submit")         #Action failed for some reason
            }
           
        }
        
    }
}
