function Get-RIDsRemaining
{
    param ($domainDN)
    $de = [ADSI]”LDAP://CN=RID Manager$,CN=System,$domainDN”
    $return = new-object system.DirectoryServices.DirectorySearcher($de)
    $property= ($return.FindOne()).properties.ridavailablepool
    [int32]$totalSIDS = $($property) / ([math]::Pow(2,32))
    [int64]$temp64val = $totalSIDS * ([math]::Pow(2,32))
    [int32]$currentRIDPoolCount = $($property) – $temp64val
    $ridsremaining = $totalSIDS – $currentRIDPoolCount
    return $currentRIDPoolCount
}

$ErrorActionPreference = "SilentlyContinue"

$DomainDN = ([adsi]"LDAP://RootDSE").defaultNamingContext
$Domain=[adsi]"LDAP://$DomainDN"
$DomainName = $Domain.name.ToString().ToLower()
$DomainSIDBytes = $Domain.Properties.ObjectSID.Value
$DomainStringSID = (New-Object System.Security.Principal.SecurityIdentifier($DomainSIDBytes,0)).Value

$LastRID = Get-RIDsRemaining($DomainDN)

for ($CurrentRID=500;$CurrentRID -lt $LastRID;$CurrentRID++)
{
 $CurrentSid="$DomainStringSID-$CurrentRID"
 $objSID = New-Object System.Security.Principal.SecurityIdentifier($CurrentSid)

 $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
 if ($objUser)
  {
    # Validate the object returned is not from another domain (due to SidHistory)
    if ($objUser.ToString().Split('\')[0].ToLower() -eq $DomainName)
    {
     $LDAPObj = [adsi]"LDAP://<SID=$CurrentSid>"
     if ($LDAPObj.Path -eq $null)
     {
      # Validate if not SIDHistory of current domain scenario - generating FPs
        $objValidatedUser = New-Object System.Security.Principal.NTAccount($objUser)
        $objValidatedSID = $objValidatedUser.Translate( [System.Security.Principal.SecurityIdentifier])
        if ($objValidatedSID.Value -eq $objSID)
        {write-host "You don't have permissions for $objUser"}
     }
    }
  }
  $objUser = $null
  $LDAPObj = $null
 }




