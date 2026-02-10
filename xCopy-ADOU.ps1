<#
.SYNOPSIS
    Copia una jerarquía completa de OUs en Active Directory de forma espejo 1:1.

.DESCRIPTION
    Script para replicación exacta de estructuras organizacionales en AD,
    incluyendo copia de vínculos GPO con orden, estado y configuración exactos.
    Soporta ejecución desatendida con logging compatible con CMTrace.

.PARAMETER OUOrigen
    Distinguished Name de la OU origen a copiar.

.PARAMETER OUDestino
    Distinguished Name de la OU destino donde se replicará la estructura.

.PARAMETER LinkGPO
    Activa la copia exacta 1:1 de vínculos GPO incluyendo orden, estado y enforcement.

.PARAMETER MoveObjects
    Mueve los objetos directos de la OU origen a la OU destino correspondiente.

.EXAMPLE
    .\xCopy-ADOU.ps1 -OUOrigen "OU=Produccion,DC=contoso,DC=com" -OUDestino "OU=Desarrollo,DC=contoso,DC=com"

.EXAMPLE
    .\xCopy-ADOU.ps1 -OUOrigen "OU=Prod,DC=contoso,DC=com" -OUDestino "OU=Dev,DC=contoso,DC=com" -LinkGPO -MoveObjects

.NOTES
    Autor: Rafael Grau (Revisado con Claude)
    Versión: 2.0
    Requisitos: Módulo ActiveDirectory, permisos de administrador de dominio
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$OUOrigen,
    
    [Parameter(Mandatory = $true)]
    [string]$OUDestino,
    
    [Parameter(Mandatory = $false)]
    [switch]$LinkGPO,
    
    [Parameter(Mandatory = $false)]
    [switch]$MoveObjects
)

#Requires -Modules ActiveDirectory

# Configuración de codificación UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

#region Funciones de Logging
# Definir nombre archivo log
$ScriptName = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Name, '.log')
$script:LogFile = Join-Path $PSScriptRoot $ScriptName

# Crear e inicializar archivo log codificado UTF8-BOM
if (-not (Test-Path $script:LogFile)) {
    $Utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($script:LogFile, "", $Utf8Bom)
}

function Write-CMTraceLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )

    $typeMap = @{ Info = 1; Warning = 2; Error = 3 }
    $typeNum = $typeMap[$Type]
    $date = Get-Date -Format 'MM-dd-yyyy'
    $time = Get-Date -Format 'HH:mm:ss.fff'
    $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $component = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.ScriptName)
    
    $logLine = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$component`" context=`"$context`" type=`"$typeNum`" thread=`"$thread`" file=`"`">"

    $Utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::AppendAllText($script:LogFile, "$logLine`r`n", $Utf8Bom)
}
#endregion

#region Funciones de GPO
function Get-GPLinkDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName
    )
    
    try {
        $ou = Get-ADOrganizationalUnit -Identity $DistinguishedName -Properties gPLink, gPOptions -ErrorAction Stop
        
        $result = @{
            GPLinks = @()
            BlockInheritance = $false
            RawGPLink = $ou.gPLink
        }
        
        # Verificar Block Inheritance
        if ($null -ne $ou.gPOptions -and $ou.gPOptions -eq 1) {
            $result.BlockInheritance = $true
        }
        
        # Parsear gPLink si existe
        if (-not [string]::IsNullOrWhiteSpace($ou.gPLink)) {
            Write-CMTraceLog -Message "  gPLink raw: $($ou.gPLink)" -Type Info
            
            # Regex para capturar cada link completo: [LDAP://...;N]
            $pattern = '\[LDAP://([^;]+);(\d+)\]'
            $linkList = [regex]::Matches($ou.gPLink, $pattern)
            
            Write-CMTraceLog -Message "  Vínculos encontrados: $($linkList.Count)" -Type Info
            
            # gPLink almacena GPOs en orden INVERSO de aplicación
            # La primera GPO vinculada es la ÚLTIMA en aplicarse
            $orderCounter = 1
            foreach ($link in $linkList) {
                $gpoDN = $link.Groups[1].Value
                $options = [int]$link.Groups[2].Value
                
                # Extraer GUID
                if ($gpoDN -match 'cn=\{([0-9a-fA-F\-]+)\}') {
                    $guid = $Matches[1]
                    
                    $gpoLink = [PSCustomObject]@{
                        GUID = $guid
                        DN = $gpoDN
                        Options = $options
                        Enabled = (($options -band 1) -eq 0)
                        Enforced = (($options -band 2) -eq 2)
                        Order = $orderCounter
                    }
                    
                    $result.GPLinks += $gpoLink
                    $orderCounter++
                    
                    Write-CMTraceLog -Message "    GPO encontrada: {$guid} Options=$options Enabled=$($gpoLink.Enabled) Enforced=$($gpoLink.Enforced)" -Type Info
                }
            }
        }
        
        return $result
    }
    catch {
        Write-CMTraceLog -Message "Error al leer los vínculos de GPO en ${DistinguishedName}: $_" -Type Error
        return $null
    }
}

function Set-GPLinkDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,
        
        [Parameter(Mandatory = $false)]
        [object]$GPLinkConfig
    )
    
    try {
        # Si no hay configuración, solo limpiar
        if ($null -eq $GPLinkConfig) {
            Set-ADOrganizationalUnit -Identity $DistinguishedName -Clear gPLink -ErrorAction SilentlyContinue
            Set-ADOrganizationalUnit -Identity $DistinguishedName -Replace @{gPOptions = 0} -ErrorAction Stop
            Write-CMTraceLog -Message "  Se han limpiado los vínculos de GPO y opciones iniciales" -Type Info
            return $true
        }
        
        # Construir nuevo gPLink
        # Importante: mantener el MISMO orden que en origen
        if ($GPLinkConfig.GPLinks.Count -gt 0) {
            $gPLinkParts = @()
            
            foreach ($link in $GPLinkConfig.GPLinks) {
                # Reconstruir el DN completo de la GPO
                # Extraer el dominio del DN de la OU destino
                $domainComponents = ($DistinguishedName -split ',' | Where-Object { $_ -match '^DC=' }) -join ','
                
                $gpoDN = "cn={$($link.GUID)},cn=policies,cn=system,$domainComponents"
                $gPLinkParts += "[LDAP://$gpoDN;$($link.Options)]"
            }
            
            # Unir todos los componentes
            $newGPLink = $gPLinkParts -join ''
            
            Write-CMTraceLog -Message "  Nuevo vínculo construido: $newGPLink" -Type Info
            Write-CMTraceLog -Message "  Total GPOs a vincular: $($GPLinkConfig.GPLinks.Count)" -Type Info
            
            # Aplicar el atributo gPLink
            Set-ADOrganizationalUnit -Identity $DistinguishedName -Replace @{gPLink = $newGPLink} -ErrorAction Stop
            
            Write-CMTraceLog -Message "  Vínculo aplicado exitosamente a $($GPLinkConfig.GPLinks.Count) GPOs" -Type Info
        }
        else {
            # No hay GPOs, limpiar
            Set-ADOrganizationalUnit -Identity $DistinguishedName -Clear gPLink -ErrorAction SilentlyContinue
            Write-CMTraceLog -Message "  Sin GPOs para vincular, gPLink limpiado" -Type Info
        }
        
        # Configurar Block Inheritance
        $gPOptionsValue = if ($GPLinkConfig.BlockInheritance) { 1 } else { 0 }
        Set-ADOrganizationalUnit -Identity $DistinguishedName -Replace @{gPOptions = $gPOptionsValue} -ErrorAction Stop
        Write-CMTraceLog -Message "  Configuración de la herencia: $($GPLinkConfig.BlockInheritance)"
        
        return $true
    }
    catch {
        Write-CMTraceLog -Message "Error al configurar los vínculos de GPO en ${DistinguishedName}: $_" -Type Error
        Write-CMTraceLog -Message "Stack: $($_.ScriptStackTrace)" -Type Error
        return $false
    }
}

function Copy-GPOLinks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceOU,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetOU
    )
    
    Write-CMTraceLog -Message "Iniciando copia de los vínculos de las GPO: $SourceOU -> $TargetOU" -Type Info
    
    # Leer configuración de origen
    $sourceConfig = Get-GPLinkDetails -DistinguishedName $SourceOU
    
    if ($null -eq $sourceConfig) {
        Write-CMTraceLog -Message "No se pudo leer configuración de GPO del origen" -Type Warning
        return
    }
    
    Write-CMTraceLog -Message "Vínculos en la Ou de origen: $($sourceConfig.GPLinks.Count)" -Type Info
    Write-CMTraceLog -Message "Bloqueo de herencia en origen: $($sourceConfig.BlockInheritance)" -Type Info
    
    # Aplicar en destino
    $result = Set-GPLinkDetails -DistinguishedName $TargetOU -GPLinkConfig $sourceConfig
    
    if ($result) {
        Write-CMTraceLog -Message "Copia de vínculos de GPO completada exitosamente" -Type Info
    }
    else {
        Write-CMTraceLog -Message "Error al copiar vínculos de GPO" -Type Error
    }
}
#endregion

#region Funciones de OU
function New-OUIfNotExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    $ouDN = "OU=$Name,$Path"
    
    try {
        $existingOU = Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction SilentlyContinue
        if ($existingOU) {
            Write-CMTraceLog -Message "OU existente: $ouDN" -Type Info
            return $existingOU
        }
    }
    catch {
        # OU no existe
    }
    
    try {
        $newOU = New-ADOrganizationalUnit -Name $Name -Path $Path -ErrorAction Stop -PassThru
        Write-CMTraceLog -Message "OU creada: $ouDN" -Type Info
        return $newOU
    }
    catch {
        Write-CMTraceLog -Message "Error al crear OU $ouDN : $_" -Type Error
        throw
    }
}

function Copy-ADOU {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceOU,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetOU,
        
        [Parameter(Mandatory = $false)]
        [bool]$CopyGPOLinks = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$MoveChildObjects = $false
    )
    
    Write-CMTraceLog -Message "Realizando la copia de la jerarquía de OU: $SourceOU ---> $TargetOU"
    
    # Crear OU destino
    try {
        $null = Get-ADOrganizationalUnit -Identity $SourceOU -ErrorAction Stop
        $targetOUName = ($TargetOU -split ',')[0] -replace 'OU=', ''
        $targetOUPath = ($TargetOU -split ',', 2)[1]
        
        $null = New-OUIfNotExists -Name $targetOUName -Path $targetOUPath
    }
    catch {
        Write-CMTraceLog -Message "Error al procesar OU: $_" -Type Error
        return
    }
    
    # Copiar GPO links
    if ($CopyGPOLinks) {
        Copy-GPOLinks -SourceOU $SourceOU -TargetOU $TargetOU
    }
    
    # Mover objetos
    if ($MoveChildObjects) {
        Move-DirectObjects -SourceOU $SourceOU -TargetOU $TargetOU
    }
    
    # Procesar OUs hijas recursivamente
    try {
        $childOUs = Get-ADOrganizationalUnit -SearchBase $SourceOU -SearchScope OneLevel -Filter * -ErrorAction Stop

        if ($childOUs.Count -gt 0) {

            Write-CMTraceLog -Message "OUs hijas encontradas: $($childOUs.Count)"
            
            foreach ($childOU in $childOUs) {
                $childName = $childOU.Name
                $newTargetOU = "OU=$childName,$TargetOU"
                
                Copy-ADOU -SourceOU $childOU.DistinguishedName -TargetOU $newTargetOU -CopyGPOLinks $CopyGPOLinks -MoveChildObjects $MoveChildObjects
            }
        }
    }
    catch {
        Write-CMTraceLog -Message "Error al obtener OUs hijas: $_" -Type Error
    }
}

function Move-DirectObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceOU,
        
        [Parameter(Mandatory = $true)]
        [string]$TargetOU
    )
    
    Write-CMTraceLog -Message "Moviendo objetos directos..."
    
    try {
        $objects = Get-ADObject -SearchBase $SourceOU -SearchScope OneLevel -Filter {ObjectClass -ne "organizationalUnit"} -ErrorAction Stop
        
        $movedCount = 0
        foreach ($obj in $objects) {
            try {
                Move-ADObject -Identity $obj.DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
                $movedCount++
                Write-CMTraceLog -Message "  Movido: $($obj.Name) ($($obj.ObjectClass))"
            }
            catch {
                Write-CMTraceLog -Message "  Error al mover $($obj.Name): $_" -Type Warning
            }
        }
        
        Write-CMTraceLog -Message "Total movidos: $movedCount de $($objects.Count)"
    }
    catch {
        Write-CMTraceLog -Message "Error al mover objetos: $_" -Type Error
    }
}
#endregion

#region Script Principal
Write-CMTraceLog -Message "-----------------------------------------------------"
Write-CMTraceLog -Message " Copia espejo de Unidades Organizativas."
Write-CMTraceLog -Message " "
Write-CMTraceLog -Message "Parámetros:"
Write-CMTraceLog -Message "  OU Origen:    $OUOrigen"
Write-CMTraceLog -Message "  OU Destino:   $OUDestino"
Write-CMTraceLog -Message "  Link GPO:     $($LinkGPO.IsPresent)"
Write-CMTraceLog -Message "  Move Objects: $($MoveObjects.IsPresent)"
Write-CMTraceLog -Message "-----------------------------------------------------"
Write-CMTraceLog -Message "Iniciando proceso..."

# Cargar módulo AD
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-CMTraceLog -Message "Módulo ActiveDirectory cargado"
}
catch {
    Write-CMTraceLog -Message "ERROR: No se pudo cargar módulo ActiveDirectory: $_" -Type Error
    exit 1
}

# Validar OU origen
try {
    $null = Get-ADOrganizationalUnit -Identity $OUOrigen -ErrorAction Stop
    Write-CMTraceLog -Message "OU origen validada"
}
catch {
    Write-CMTraceLog -Message "ERROR: OU origen no encontrada: $OUOrigen" -Type Error
    exit 1
}

# Ejecutar copia
try {
    Copy-ADOU -SourceOU $OUOrigen -TargetOU $OUDestino -CopyGPOLinks $LinkGPO.IsPresent -MoveChildObjects $MoveObjects.IsPresent
    
    Write-CMTraceLog -Message " Proceso finalizado."
}
catch {
    Write-CMTraceLog -Message "ERROR CRÍTICO: $_" -Type Error
    Write-CMTraceLog -Message "Stack: $($_.ScriptStackTrace)" -Type Error
    exit 1
}

#endregion
