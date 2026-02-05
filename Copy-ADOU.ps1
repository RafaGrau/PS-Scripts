<#
.SYNOPSIS
Clona en espejo una estructura de Unidades Organizativas (OU) en Active Directory.

.DESCRIPTION
Este script/función copia en espejo la jerarquía completa de Unidades Organizativas
desde una OU de origen hacia una OU de destino.

El proceso incluye:
- Creación automática de la OU destino si no existe
- Copia de toda la estructura de OUs (padre e hijas)
- Copia del estado de Block Inheritance
- Copia de delegaciones de seguridad (ACLs)
- Copia opcional de enlaces de GPO (sin duplicados, respetando orden, estado y enforced)

No se copian objetos de AD como usuarios, equipos o grupos.
No se eliminan GPOs existentes en el destino (modo seguro por defecto).

El script soporta ejecución segura mediante -WhatIf y -Confirm
y genera un log compatible con CMTrace.exe.

.PARAMETER OUOrigen
Distinguished Name (DN) de la Unidad Organizativa origen.

Ejemplo:
OU=Origen,DC=empresa,DC=local

.PARAMETER OUDestino
Distinguished Name (DN) de la Unidad Organizativa destino.

Si no existe, será creada automáticamente.

Ejemplo:
OU=Destino,DC=empresa,DC=local

.PARAMETER LinkGPO
Indica que deben copiarse también los enlaces de GPO desde la OU origen
a la OU destino, respetando:
- Orden del enlace
- Estado habilitado/deshabilitado
- Enforced (forzado)

Si no se especifica, solo se copia la estructura de OUs y su configuración.

.EXAMPLE
Simulación completa sin realizar cambios en Active Directory:

Copy-ADOU `
  -OUOrigen "OU=Origen,DC=empresa,DC=local" `
  -OUDestino "OU=Destino,DC=empresa,DC=local" `
  -LinkGPO `
  -WhatIf

.EXAMPLE
Ejecución real copiando estructura de OUs y enlaces de GPO:

Copy-ADOU `
  -OUOrigen "OU=Origen,DC=empresa,DC=local" `
  -OUDestino "OU=Destino,DC=empresa,DC=local" `
  -LinkGPO `
  -Verbose

.EXAMPLE
Copiar solo la estructura de OUs (sin GPOs):

Copy-ADOU `
  -OUOrigen "OU=Origen,DC=empresa,DC=local" `
  -OUDestino "OU=Destino,DC=empresa,DC=local"

.NOTES
Autor: Rafael Grau (depurado con ChatGPT)
Requisitos:
- Módulos ActiveDirectory y GroupPolicy
- Permisos para crear OUs, enlazar GPOs y modificar ACLs
- Ejecutar desde un equipo con RSAT

El archivo de log se genera en el directorio de ejecución con el formato:
NombreDelScript-AAAAmmDD_HHmm.log

.LINK
Get-Help Copy-ADOU -Full
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OUOrigen,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OUDestino,

    [switch]$LinkGPO
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

#region Logging (CMTrace compatible)

$ScriptName = [System.IO.Path]::GetFileNameWithoutExtension(
    $MyInvocation.MyCommand.Name
)

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmm"
$LogFile   = Join-Path `
    -Path (Get-Location) `
    -ChildPath "$ScriptName-$TimeStamp.log"

if (-not (Test-Path $LogFile)) {Out-File -FilePath $LogFile -Encoding Unicode}

function Write-CMTraceLog {
    param (
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Level = 'Info'
    )

    $Type = switch ($Level) {
        'Info'    { 1 }
        'Warning' { 2 }
        'Error'   { 3 }
    }

    $Time = Get-Date -Format "HH:mm:ss.fff"
    $Date = Get-Date -Format "MM-dd-yyyy"

    $LogLine = "<![LOG[$Message]LOG]!><time=""$Time"" date=""$Date"" component=""Copy-ADOU"" context="""" type=""$Type"" thread="""" file="""">"

    Add-Content -Path $LogFile -Value $LogLine
}

#endregion

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy     -ErrorAction Stop

#region Helper functions

function Test-OUExists {
    param ([string]$DN)
    try {
        Get-ADOrganizationalUnit -Identity $DN -ErrorAction Stop | Out-Null
        $true
    } catch { $false }
}

function Get-RelativeDN {
    param ($ChildDN, $BaseDN)
    $ChildDN.Substring(0, $ChildDN.Length - $BaseDN.Length)
}

#endregion

Write-CMTraceLog "Inicio de ejecución"

#region Crear OU destino raíz

if (-not (Test-OUExists $OUDestino)) {

    if ($OUDestino -match '^OU=([^,]+),(.*)$') {

        if ($PSCmdlet.ShouldProcess($OUDestino, "Crear OU destino")) {

            New-ADOrganizationalUnit -Name $matches[1] -Path $matches[2]
            Write-CMTraceLog "OU destino creada: $OUDestino"
        }
    }
    else {
        Write-CMTraceLog "DN destino inválido: $OUDestino" Error
        throw "DN destino inválido"
    }
}

#endregion

#region Obtener OUs origen

$SourceOUs = Get-ADOrganizationalUnit `
    -SearchBase $OUOrigen `
    -Filter * |
    Sort-Object { $_.DistinguishedName.Split(',').Count }

#endregion

#region Copiar estructura de OUs

foreach ($SourceOU in $SourceOUs) {

    $RelativeDN = Get-RelativeDN $SourceOU.DistinguishedName $OUOrigen
    $TargetOU  = "$RelativeDN$OUDestino"

    if (-not (Test-OUExists $TargetOU)) {

        if ($TargetOU -match '^OU=([^,]+),(.*)$') {

            if ($PSCmdlet.ShouldProcess($TargetOU, "Crear OU")) {

                New-ADOrganizationalUnit -Name $matches[1] -Path $matches[2]
                Write-CMTraceLog "OU creada: $TargetOU"
            }
        }
    }
}

#endregion

#region Copiar Block Inheritance

foreach ($SourceOU in $SourceOUs) {

    $RelativeDN = Get-RelativeDN $SourceOU.DistinguishedName $OUOrigen
    $TargetOU  = "$RelativeDN$OUDestino"

    $Src = Get-GPInheritance -Target $SourceOU.DistinguishedName
    $Dst = Get-GPInheritance -Target $TargetOU

    if ($Src.BlockInheritance -ne $Dst.BlockInheritance) {

        if ($PSCmdlet.ShouldProcess($TargetOU, "Configurar Block Inheritance")) {

            Set-GPInheritance -Target $TargetOU -IsBlocked $Src.BlockInheritance
            Write-CMTraceLog "Block Inheritance configurado en $TargetOU"
        }
    }
}

#endregion

#region Copiar enlaces de GPO (sin duplicados, respetando orden)

if ($LinkGPO) {

    foreach ($SourceOU in $SourceOUs) {

        $RelativeDN = Get-RelativeDN $SourceOU.DistinguishedName $OUOrigen
        $TargetOU  = "$RelativeDN$OUDestino"

        $SrcLinks = (Get-GPInheritance -Target $SourceOU.DistinguishedName).GpoLinks
        $DstLinks = (Get-GPInheritance -Target $TargetOU).GpoLinks

        foreach ($Link in $SrcLinks) {

            if ($DstLinks.DisplayName -contains $Link.DisplayName) {
                Write-CMTraceLog "GPO ya vinculada, se omite: $($Link.DisplayName)" Warning
                continue
            }

            $EnforcedValue = if ($Link.Enforced) {
                [Microsoft.GroupPolicy.EnforceLink]::Yes
            } else {
                [Microsoft.GroupPolicy.EnforceLink]::No
            }

            $LinkEnabledValue = if ($Link.Enabled -eq 'Yes') {
                [Microsoft.GroupPolicy.EnableLink]::Yes
            } else {
                [Microsoft.GroupPolicy.EnableLink]::No
            }

            if ($PSCmdlet.ShouldProcess(
                $TargetOU,
                "Vincular GPO '$($Link.DisplayName)'"
            )) {

                New-GPLink `
                    -Name $Link.DisplayName `
                    -Target $TargetOU `
                    -Order $Link.Order `
                    -Enforced $EnforcedValue `
                    -LinkEnabled $LinkEnabledValue `
                    | Out-Null

                Write-CMTraceLog "GPO vinculada '$($Link.DisplayName)' en $TargetOU"
            }
        }
    }
}

#endregion

#region Copiar delegaciones de seguridad

foreach ($SourceOU in $SourceOUs) {

    $RelativeDN = Get-RelativeDN $SourceOU.DistinguishedName $OUOrigen
    $TargetOU  = "$RelativeDN$OUDestino"

    if ($PSCmdlet.ShouldProcess($TargetOU, "Copiar ACLs")) {

        $ACL = Get-Acl "AD:$($SourceOU.DistinguishedName)"
        Set-Acl -Path "AD:$TargetOU" -AclObject $ACL

        Write-CMTraceLog "ACLs copiadas a $TargetOU"
    }
}

#endregion

Write-CMTraceLog "Fin de ejecución"