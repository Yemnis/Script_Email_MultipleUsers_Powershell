# Function to generate new random password.
function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length
    )
    $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{]+-[*=@:)}$^%;(_!&amp;#?>/|.'.ToCharArray()
    # $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
 
    $rng.GetBytes($bytes)
 
    $result = New-Object char[]($length)
 
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $charSet[$bytes[$i]%$charSet.Length]
    }
 
    return (-join $result)
}


$ErrorActionPreference = "Stop"


# Add your path below and remove C:\UsersInfoFromThisDocument.csv
$content = Import-Csv -Path "C:\UsersInfoFromThisDocument.csv" -Delimiter ";" -Encoding UTF7


foreach($user in $content)
{
    # ActiveUser. The title of the column should replace Column 1
    $mail = $user.Column1.Trim();

    # The relevant server should replace should replace server.servername.com below
    $adAccount = Get-aduser -Filter "mail -eq '$($mail)'" -Server server.servername.com 

    if($adAccount)
    {
        try 
        {

        Set-ADUser -Identity $adAccount.SamAccountName -Enabled $true -Server server.servername.com

        # Generate Random Temporary Password, 12 characters long.
        $password = Get-RandomPassword 12
        $passwordSec = ConvertTo-SecureString -AsPlainText $password -Force

        # Add password generated above to the user's account
        Set-ADAccountPassword -Identity $adAccount.SamAccountName -NewPassword $passwordSec -Reset -Confirm:$false -Server server.servername.com -ErrorAction Stop

        
        # Send Welcome message to new user(s)
        $MailBody = "
   
        Hello and welcome to XYZ,

        ##   Welcome them here and send relevant message and attachments  ##

        Username: $($user.Column1)

        All the best,
        Company xyz"


        # Update and replace -SmtpServer, -from, and -to as needed.
        Send-MailMessage -Subject "Welcome to Company xyz" -Body $MailBody -SmtpServer gotmail.companyxyz.com -from "Dev.informationnoreply@companyxyz.com" -to $user.Mailadress
        Send-MailMessage -Subject "Your new password" -Body "$password" -SmtpServer gotmail.companyxyz.com -from "Dev.informationnoreply@companyxyz.com" -to $user.Mailadress

        }
        catch
        {
        
            "$($adaccount.samaccountname), $password , $($User.mailadress)" >> 'C:\xxxyyyzzz\log_details.txt'
        
        }
    }


}
