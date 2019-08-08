try {

# import AD module
Import-Module ActiveDirectory

# specify csv file path
$file = "importCSV.csv"

# import csv file
$users = Import-Csv $file

# Removes old log file, to show user new log...
Remove-Item 'faculty-errors.txt'

#FOR LOOP TO DETERMINE HOW MANY USERS
ForEach($user in $users) {

# input user information
$name = $user.Name
$givenname = $user.GivenName
$surname = $user.Surname
$ad_password = $user.Password
$homedrive = $user.HomeDrive
$displayname = $user.DisplayName
$fullName = $user.SamAccountName
$building = $user.building

$ErrorActionPreference = "Continue"
$OutputFileLocation = "faculty-errors.txt"
Start-Transcript -path $OutputFileLocation -append

$HomeDirectoryPartOne = "\\faculty\"
If ($buiding -eq "Admin") {
    $HomeDirectoryPartTwo = "Admin-Home$\"
    $script = "adlogon.bat"
    $ou_path = "OU=Admin,OU=Faculty,DC=vv,DC=local"
} ElseIf ($building -eq "Cafeteria") {
    $HomeDirectoryPartTwo = "Cafe-Home$\"
     $script = "cafelogon.bat"
     $ou_path = "OU=Cafeteria,OU=Faculty,DC=vv,DC=local"
} ElseIf ($building -eq "Elementary") {
    $HomeDirectoryPartTwo = "Elementary-Home$\"
     $script = "ellogon.bat"
     $ou_path = "OU=Elementary,OU=Faculty,DC=vv,DC=local"
} ElseIf ($building -eq "HighSchool") {
    $HomeDirectoryPartTwo = "HighSchool-Home$\"
     $script = "hslogon.bat"
     $ou_path = "OU=HighSchool,OU=Faculty,DC=vv,DC=local"
} ElseIf ($building -eq "Intermediate") {
    $HomeDirectoryPartTwo = "Inter-Home$\"
     $script = "intlogon.bat"
     $ou_path = "OU=Intermediate,OU=Faculty,DC=vv,DC=local"
} ElseIf ($building -eq "JrHigh") {
    $HomeDirectoryPartTwo = "JrHigh-Home$\"
     $script = "jrlogon.bat"
     $ou_path = "OU=JrHigh,OU=Faculty,DC=vv,DC=local"
} ElseIf ($building -eq "Misc") {
    $HomeDirectoryPartTwo = "Misc-Home$\"
     $script = "misclogon.bat"
     $ou_path = "OU=Misc,OU=Faculty,DC=vv,DC=local"
} ElseIf ($building -eq "PreK") {
    $HomeDirectoryPartTwo = "PreKHome$\"
     $script = "prelogon.bat"
     $ou_path = "OU=PreK,OU=Faculty,DC=vv,DC=local"
} Else {
    "ERROR!!"
}

#ADDS ENTIRE HOME DIRECTORY
$HomeDirectoryPutTogether = $HomeDirectoryPartOne + $HomeDirectoryPartTwo + $fullName

#Create Home Folder
New-Item -ItemType directory -Path $HomeDirectoryPutTogether

# convert password to secure password
$secure_password = ConvertTo-SecureString $ad_password -AsPlainText -Force

# create ad account
New-ADUser -Name "$givenname$surname" -GivenName $givenname `
-Surname $surname -UserPrincipalName ("$name$surname" + "@vv.local") -Path $ou_path `
-AccountPassword $secure_password -ChangePasswordAtLogon $true -Enabled $true `
-displayName $displayname `
-HomeDirectory $HomeDirectoryPutTogether -HomeDrive $homedrive -ScriptPath $script

#join to object group so it can map drives
Add-ADGroupMember -Identity Faculty -Members $fullName

#DEFINE PERMISSIONS
$path = "$HomeDirectoryPutTogether" #Replace with whatever file you want to do this to.
$user = "VV\$fullName" #User account to grant permisions too.
$Rights = "FullControl" #Comma seperated list.
$InheritSettings = "Containerinherit, ObjectInherit" #Controls how permissions are inherited by children
$PropogationSettings = "None" #Usually set to none but can setup rules that only apply to children.
$RuleType = "Allow" #Allow or Deny.

#ENABLE PERMISSIONS
$acl = Get-Acl $path
$perm = $user, $Rights, $InheritSettings, $PropogationSettings, $RuleType
$rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $perm
$acl.SetAccessRule($rule)
$acl | Set-Acl -Path $path

Stop-Transcript

}

} catch {

    Write-Output "ERROR!: See Log File, faculty-errors.txt"

}
