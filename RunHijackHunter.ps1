#primarily based on a the script from Petr Hinchley here: https://gist.github.com/hinchley/ade9528e5ce986e9a8131489ad852789 
#modified it to use the results to feed hijackhunter from @matterpreter at his OffensiveCSharp repo here: https://github.com/matterpreter/OffensiveCSharp 

# Paths that we've already excluded via AppLocker.
$exclusions = @()


# Paths to process.
$paths = @(
  "C:\"
)

# Setup log.
$log = "$PSScriptRoot\UserWritableLocations.log"

$FSR = [System.Security.AccessControl.FileSystemRights]

# Unfortunately the FileSystemRights enum doesn't contain all the values from the Win32 API. Urgh.
$GenericRights = @{
  GENERIC_READ    = [int]0x80000000;
  GENERIC_WRITE   = [int]0x40000000;
  GENERIC_EXECUTE = [int]0x20000000;
  GENERIC_ALL     = [int]0x10000000;
  FILTER_GENERIC  = [int]0x0FFFFFFF;
}

# ... so we need to map them ourselves.
$MappedGenericRights = @{
  FILE_GENERIC_READ    = $FSR::ReadAttributes -bor $FSR::ReadData -bor $FSR::ReadExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
  FILE_GENERIC_WRITE   = $FSR::AppendData -bor $FSR::WriteAttributes -bor $FSR::WriteData -bor $FSR::WriteExtendedAttributes -bor $FSR::ReadPermissions -bor $FSR::Synchronize
  FILE_GENERIC_EXECUTE = $FSR::ExecuteFile -bor $FSR::ReadPermissions -bor $FSR::ReadAttributes -bor $FSR::Synchronize
  FILE_GENERIC_ALL     = $FSR::FullControl
}

Function Map-GenericRightsToFileSystemRights([System.Security.AccessControl.FileSystemRights]$Rights) {  
  $MappedRights = New-Object -TypeName $FSR

  if ($Rights -band $GenericRights.GENERIC_EXECUTE) {
    $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_EXECUTE
  }

  if ($Rights -band $GenericRights.GENERIC_READ) {
   $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_READ
  }

  if ($Rights -band $GenericRights.GENERIC_WRITE) {
    $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_WRITE
  }

  if ($Rights -band $GenericRights.GENERIC_ALL) {
    $MappedRights = $MappedRights -bor $MappedGenericRights.FILE_GENERIC_ALL
  }

  return (($Rights -band $GenericRights.FILTER_GENERIC) -bor $MappedRights) -as $FSR
}

# These are the rights from the FileSystemRights enum we care about.
$WriteRights = @('WriteData', 'CreateFiles', 'CreateDirectories', 'WriteExtendedAttributes', 'WriteAttributes', 'Write', 'Modify', 'FullControl')

# Helper function to match against a list of patterns.
function notlike($string, $patterns) {  
  foreach ($pattern in $patterns) { if ($string -like $pattern) { return $false } }
  return $true
}

# The hard work...
function scan($path, $log) {  
  $cache = @()
  gci $path -recurse -exclude $exclusions -force -ea silentlycontinue |
  ? {($_.psiscontainer) -and (notlike $_.fullname $exclusions)} | %{
    trap { continue }
    $directory = $_.fullname
    (get-acl $directory -ea silentlycontinue).access |
    #? {$_.isinherited -eq $false} |  #I commented this line out.
    ? {$_.identityreference -match ".*USERS|EVERYONE"} | %{
      (map-genericrightstofilesystemrights $_.filesystemrights).tostring().split(",") | %{
        if ($writerights -contains $_.trim()) {
          if ($cache -notcontains $directory) { $cache += $directory }
        }
      }
    }
  }
  return $cache
}

# Start scanning.
$WritableFolders = $paths | %{ scan $_ $log } 


write-host "********************************************************"
write-host "****************** Writable Folders ********************"
write-host "********************************************************"
$WritableFolders

write-host "********************************************************"
write-host "****************** Hijack Hunter Results ***************"
write-host "********************************************************"

$AllExesToCheck = @() #just a variable to hold all of the exe's we find in the writable folder

#loop through each writable folder and find exe's
foreach ($WritableFolder in $WritableFolders)
{
    try
    {
        $FoundExes = gci -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -InformationAction SilentlyContinue  $WritableFolder -Filter *.exe  2>&1 
        if ($FoundExes -ne $null -and $FoundExes.count -gt 0)
        {
            $AllExesToCheck += $FoundExes
        }
    }
    catch
    {
    }
}


#loop through all the exe's and run hijack hunter against it
foreach ($exe in $AllExesToCheck)
{
    try
    {
       $error.Clear()
       $results =  C:\Users\Public\HijackHunter.exe "$($exe.FullName)" -quiet 2>&1  


       if ($error.Count -eq 0 )
       {
            foreach ($result in $results)
            {
                if ($result.Contains("is hijackable"))
                {
                     $results
                }
            }
            
       }
    }
    catch
    {}
}

