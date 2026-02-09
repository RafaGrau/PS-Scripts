<#
.SYNOPSIS
    Copia una jerarquía completa de OUs en Active Directory de forma espejo 1:1.

.DESCRIPTION
    Script enterprise para replicación exacta de estructuras organizacionales en AD,
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
    .\Copy-ADOUHierarchy.ps1 -OUOrigen "OU=Produccion,DC=contoso,DC=com" -OUDestino "OU=Desarrollo,DC=contoso,DC=com"

.EXAMPLE
    .\Copy-ADOUHierarchy.ps1 -OUOrigen "OU=Prod,DC=contoso,DC=com" -OUDestino "OU=Dev,DC=contoso,DC=com" -LinkGPO -MoveObjects

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
function Write-CMTraceLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Type = 'Info',
        
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )

    $typeMap = @{ Info = 1; Warning = 2; Error = 3 }
    $typeNum = $typeMap[$Type]
    $date = Get-Date -Format 'M-d-yyyy'
    $time = Get-Date -Format 'HH:mm:ss.ffffff'
    $context = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $thread = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $logLine = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$scriptName`" context=`"$context`" type=`"$typeNum`" thread=`"$thread`" file=`"`">"

    $utf8BOM = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::AppendAllText($LogFile, "$logLine`r`n", $utf8BOM)
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
            Write-CMTraceLog -Message "  gPLink raw: $($ou.gPLink)" -Type Info -LogFile $LogFile
            
            # Regex para capturar cada link completo: [LDAP://...;N]
            $pattern = '\[LDAP://([^;]+);(\d+)\]'
            $matches = [regex]::Matches($ou.gPLink, $pattern)
            
            Write-CMTraceLog -Message "  Matches encontrados: $($matches.Count)" -Type Info -LogFile $LogFile
            
            # gPLink almacena GPOs en orden INVERSO de aplicación
            # La primera GPO en gPLink es la ÚLTIMA en aplicarse
            $orderCounter = 1
            foreach ($match in $matches) {
                $gpoDN = $match.Groups[1].Value
                $options = [int]$match.Groups[2].Value
                
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
                    
                    Write-CMTraceLog -Message "    GPO encontrada: {$guid} Options=$options Enabled=$($gpoLink.Enabled) Enforced=$($gpoLink.Enforced)" -Type Info -LogFile $LogFile
                }
            }
        }
        
        return $result
    }
    catch {
        Write-CMTraceLog -Message "Error al leer GPO links de ${DistinguishedName}: $_" -Type Error -LogFile $LogFile
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
            Write-CMTraceLog -Message "  GPLinks y opciones limpiados" -Type Info -LogFile $LogFile
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
            
            Write-CMTraceLog -Message "  Nuevo gPLink construido: $newGPLink" -Type Info -LogFile $LogFile
            Write-CMTraceLog -Message "  Total GPOs a vincular: $($GPLinkConfig.GPLinks.Count)" -Type Info -LogFile $LogFile
            
            # Aplicar el atributo gPLink
            Set-ADOrganizationalUnit -Identity $DistinguishedName -Replace @{gPLink = $newGPLink} -ErrorAction Stop
            
            Write-CMTraceLog -Message "  gPLink aplicado exitosamente con $($GPLinkConfig.GPLinks.Count) GPOs" -Type Info -LogFile $LogFile
        }
        else {
            # No hay GPOs, limpiar
            Set-ADOrganizationalUnit -Identity $DistinguishedName -Clear gPLink -ErrorAction SilentlyContinue
            Write-CMTraceLog -Message "  Sin GPOs para vincular, gPLink limpiado" -Type Info -LogFile $LogFile
        }
        
        # Configurar Block Inheritance
        $gPOptionsValue = if ($GPLinkConfig.BlockInheritance) { 1 } else { 0 }
        Set-ADOrganizationalUnit -Identity $DistinguishedName -Replace @{gPOptions = $gPOptionsValue} -ErrorAction Stop
        Write-CMTraceLog -Message "  Block Inheritance: $($GPLinkConfig.BlockInheritance)" -Type Info -LogFile $LogFile
        
        return $true
    }
    catch {
        Write-CMTraceLog -Message "Error al configurar GPLinks en ${DistinguishedName}: $_" -Type Error -LogFile $LogFile
        Write-CMTraceLog -Message "Stack: $($_.ScriptStackTrace)" -Type Error -LogFile $LogFile
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
    
    Write-CMTraceLog -Message "Iniciando copia de GPO links: $SourceOU -> $TargetOU" -Type Info -LogFile $LogFile
    
    # Leer configuración de origen
    $sourceConfig = Get-GPLinkDetails -DistinguishedName $SourceOU
    
    if ($null -eq $sourceConfig) {
        Write-CMTraceLog -Message "No se pudo leer configuración de GPO del origen" -Type Warning -LogFile $LogFile
        return
    }
    
    Write-CMTraceLog -Message "GPOs encontradas en origen: $($sourceConfig.GPLinks.Count)" -Type Info -LogFile $LogFile
    Write-CMTraceLog -Message "Block Inheritance en origen: $($sourceConfig.BlockInheritance)" -Type Info -LogFile $LogFile
    
    # Aplicar en destino
    $result = Set-GPLinkDetails -DistinguishedName $TargetOU -GPLinkConfig $sourceConfig
    
    if ($result) {
        Write-CMTraceLog -Message "Copia de GPO links completada exitosamente" -Type Info -LogFile $LogFile
    }
    else {
        Write-CMTraceLog -Message "Error al copiar GPO links" -Type Error -LogFile $LogFile
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
            Write-CMTraceLog -Message "OU existente: $ouDN" -Type Info -LogFile $LogFile
            return $existingOU
        }
    }
    catch {
        # OU no existe
    }
    
    try {
        $newOU = New-ADOrganizationalUnit -Name $Name -Path $Path -ErrorAction Stop -PassThru
        Write-CMTraceLog -Message "OU creada: $ouDN" -Type Info -LogFile $LogFile
        return $newOU
    }
    catch {
        Write-CMTraceLog -Message "Error al crear OU $ouDN : $_" -Type Error -LogFile $LogFile
        throw
    }
}

function Copy-OUHierarchy {
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
    
    Write-CMTraceLog -Message "========================================" -Type Info -LogFile $LogFile
    Write-CMTraceLog -Message "Procesando: $SourceOU" -Type Info -LogFile $LogFile
    Write-CMTraceLog -Message "Destino: $TargetOU" -Type Info -LogFile $LogFile
    
    # Crear OU destino
    try {
        $sourceOUObj = Get-ADOrganizationalUnit -Identity $SourceOU -ErrorAction Stop
        $targetOUName = ($TargetOU -split ',')[0] -replace 'OU=', ''
        $targetOUPath = ($TargetOU -split ',', 2)[1]
        
        $targetOUObj = New-OUIfNotExists -Name $targetOUName -Path $targetOUPath
    }
    catch {
        Write-CMTraceLog -Message "Error al procesar OU: $_" -Type Error -LogFile $LogFile
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
        
        Write-CMTraceLog -Message "OUs hijas encontradas: $($childOUs.Count)" -Type Info -LogFile $LogFile
        
        foreach ($childOU in $childOUs) {
            $childName = $childOU.Name
            $newTargetOU = "OU=$childName,$TargetOU"
            
            Copy-OUHierarchy -SourceOU $childOU.DistinguishedName -TargetOU $newTargetOU -CopyGPOLinks $CopyGPOLinks -MoveChildObjects $MoveChildObjects
        }
    }
    catch {
        Write-CMTraceLog -Message "Error al obtener OUs hijas: $_" -Type Error -LogFile $LogFile
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
    
    Write-CMTraceLog -Message "Moviendo objetos directos..." -Type Info -LogFile $LogFile
    
    try {
        $objects = Get-ADObject -SearchBase $SourceOU -SearchScope OneLevel -Filter {ObjectClass -ne "organizationalUnit"} -ErrorAction Stop
        
        $movedCount = 0
        foreach ($obj in $objects) {
            try {
                Move-ADObject -Identity $obj.DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
                $movedCount++
                Write-CMTraceLog -Message "  Movido: $($obj.Name) ($($obj.ObjectClass))" -Type Info -LogFile $LogFile
            }
            catch {
                Write-CMTraceLog -Message "  Error al mover $($obj.Name): $_" -Type Warning -LogFile $LogFile
            }
        }
        
        Write-CMTraceLog -Message "Total movidos: $movedCount de $($objects.Count)" -Type Info -LogFile $LogFile
    }
    catch {
        Write-CMTraceLog -Message "Error al mover objetos: $_" -Type Error -LogFile $LogFile
    }
}
#endregion

#region Script Principal

# Inicializar log
$ScriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmm"
$LogFile    = Join-Path $PSScriptRoot "$ScriptName`_$Timestamp.log"

# Crear archivo con UTF8-BOM.
$Utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($LogFile, "", $Utf8Bom)

Write-CMTraceLog -Message "========================================" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "INICIO: Copy-ADOUHierarchy" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "========================================" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "Parámetros:" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "  OU Origen: $OUOrigen" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "  OU Destino: $OUDestino" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "  Link GPO: $($LinkGPO.IsPresent)" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "  Move Objects: $($MoveObjects.IsPresent)" -Type Info -LogFile $LogFile
Write-CMTraceLog -Message "========================================" -Type Info -LogFile $LogFile

# Cargar módulo AD
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-CMTraceLog -Message "Módulo ActiveDirectory cargado" -Type Info -LogFile $LogFile
}
catch {
    Write-CMTraceLog -Message "ERROR: No se pudo cargar módulo ActiveDirectory: $_" -Type Error -LogFile $LogFile
    exit 1
}

# Validar OU origen
try {
    $null = Get-ADOrganizationalUnit -Identity $OUOrigen -ErrorAction Stop
    Write-CMTraceLog -Message "OU origen validada" -Type Info -LogFile $LogFile
}
catch {
    Write-CMTraceLog -Message "ERROR: OU origen no encontrada: $OUOrigen" -Type Error -LogFile $LogFile
    exit 1
}

# Ejecutar copia
try {
    Copy-OUHierarchy -SourceOU $OUOrigen -TargetOU $OUDestino -CopyGPOLinks $LinkGPO.IsPresent -MoveChildObjects $MoveObjects.IsPresent
    
    Write-CMTraceLog -Message "========================================" -Type Info -LogFile $LogFile
    Write-CMTraceLog -Message "COMPLETADO EXITOSAMENTE" -Type Info -LogFile $LogFile
    Write-CMTraceLog -Message "========================================" -Type Info -LogFile $LogFile
}
catch {
    Write-CMTraceLog -Message "ERROR CRÍTICO: $_" -Type Error -LogFile $LogFile
    Write-CMTraceLog -Message "Stack: $($_.ScriptStackTrace)" -Type Error -LogFile $LogFile
    exit 1
}

#endregion
