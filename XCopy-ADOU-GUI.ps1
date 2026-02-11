<#
.SYNOPSIS
    Interfaz gráfica para copia espejo de OUs en Active Directory.

.DESCRIPTION
    Herramienta GUI para copiar jerarquías completas de OUs con selección visual,
    copia de vínculos GPO, movimiento de objetos y log en tiempo real.

.NOTES
    Versión: 3.0
    Autor:  Rafael Grau (Revisado con Claude)
#>

#Requires -Modules ActiveDirectory

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

#region Variables Globales
$script:SourceOU = $null
$script:TargetOU = $null
$script:LogFile = $null
$script:LogBox = $null
#endregion

#region Logging
function Initialize-Log {
    $logName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath) + ".log"
    $logDir = Split-Path -Parent $PSCommandPath
    $script:LogFile = Join-Path $logDir $logName
    
    # Crear con UTF8-BOM
    $utf8 = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($script:LogFile, "", $utf8)
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error')]
        [string]$Type = 'Info'
    )
    
    # Mapeo de severidad
    $severity = @{Info=1; Warning=2; Error=3}[$Type]
    
    # Formato CMTrace
    $time = Get-Date -Format 'HH:mm:ss.fff+000'
    $date = Get-Date -Format 'MM-dd-yyyy'
    $component = 'Copy-ADOU-GUI'
    $context = ''
    $thread = $PID
    $file = ''
    
    $line = "<![LOG[$Message]LOG]!><time=`"$time`" date=`"$date`" component=`"$component`" context=`"$context`" type=`"$severity`" thread=`"$thread`" file=`"$file`">"
    
    # Escribir a archivo
    $utf8 = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::AppendAllText($script:LogFile, "$line`r`n", $utf8)
    
    # Escribir a GUI
    if ($script:LogBox) {
        $prefix = @{Info='[INFO] '; Warning='[WARN] '; Error='[ERROR]'}[$Type]
        $stamp = Get-Date -Format 'HH:mm:ss'
        $text = "$stamp $prefix$Message`r`n"
        
        $script:LogBox.AppendText($text)
        $script:LogBox.SelectionStart = $script:LogBox.TextLength
        $script:LogBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }
}
#endregion

#region Funciones AD
function Get-GPOLinks {
    param([string]$DN)
    
    try {
        $ou = Get-ADOrganizationalUnit $DN -Properties gPLink,gPOptions -ErrorAction Stop
        
        $links = @()
        $block = ($ou.gPOptions -eq 1)
        
        if ($ou.gPLink) {
            $pattern = '\[LDAP://([^;]+);(\d+)\]'
            $matches = [regex]::Matches($ou.gPLink, $pattern)
            
            foreach ($m in $matches) {
                $gpoDN = $m.Groups[1].Value
                $opts = [int]$m.Groups[2].Value
                
                if ($gpoDN -match '{([^}]+)}') {
                    $links += @{
                        GUID = $Matches[1]
                        Options = $opts
                    }
                }
            }
        }
        
        return @{Links = $links; Block = $block}
    }
    catch {
        Write-Log "Error leyendo GPO de $DN : $_" Error
        return $null
    }
}

function Set-GPOLinks {
    param(
        [string]$DN,
        [object]$Config
    )
    
    try {
        if (!$Config -or $Config.Links.Count -eq 0) {
            Set-ADOrganizationalUnit $DN -Clear gPLink -ErrorAction SilentlyContinue
            Set-ADOrganizationalUnit $DN -Replace @{gPOptions=0} -ErrorAction Stop
            return $true
        }
        
        # Construir gPLink
        $domain = ($DN -split ',' | Where-Object {$_ -match '^DC='}) -join ','
        $linkStr = ''
        
        foreach ($link in $Config.Links) {
            $gpo = "cn={$($link.GUID)},cn=policies,cn=system,$domain"
            $linkStr += "[LDAP://$gpo;$($link.Options)]"
        }
        
        Set-ADOrganizationalUnit $DN -Replace @{gPLink=$linkStr} -ErrorAction Stop
        $gpValue = if ($Config.Block) {1} else {0}
        Set-ADOrganizationalUnit $DN -Replace @{gPOptions=$gpValue} -ErrorAction Stop
        
        return $true
    }
    catch {
        Write-Log "Error aplicando GPO a $DN : $_" Error
        return $false
    }
}

function Copy-OUTree {
    param(
        [string]$Source,
        [string]$Target,
        [bool]$CopyGPO,
        [bool]$MoveObjs
    )
    
    Write-Log "Procesando: $Source -> $Target"
    [System.Windows.Forms.Application]::DoEvents()
    
    # Crear OU destino
    try {
        # Verificar si existe
        try {
            $null = Get-ADOrganizationalUnit $Target -ErrorAction Stop
            Write-Log "OU destino existe: $Target"
        }
        catch {
            # No existe, crear
            $name = ($Target -split ',',2)[0] -replace 'OU=',''
            $path = ($Target -split ',',2)[1]
            
            $null = New-ADOrganizationalUnit -Name $name -Path $path -ErrorAction Stop
            Write-Log "OU creada: $Target"
        }
    }
    catch {
        Write-Log "Error creando OU $Target : $_" Error
        return
    }
    
    # Copiar GPO
    if ($CopyGPO) {
        $gpo = Get-GPOLinks $Source
        if ($gpo) {
            Write-Log "Copiando $($gpo.Links.Count) GPOs"
            Set-GPOLinks $Target $gpo | Out-Null
        }
    }
    
    # Mover objetos
    if ($MoveObjs) {
        try {
            $objs = Get-ADObject -SearchBase $Source -SearchScope OneLevel -Filter {ObjectClass -ne 'organizationalUnit'}
            $moved = 0
            
            foreach ($obj in $objs) {
                try {
                    Move-ADObject $obj.DistinguishedName -TargetPath $Target -ErrorAction Stop
                    $moved++
                }
                catch {
                    Write-Log "Error moviendo $($obj.Name): $_" Warning
                }
            }
            
            Write-Log "Objetos movidos: $moved/$($objs.Count)"
        }
        catch {
            Write-Log "Error moviendo objetos: $_" Error
        }
    }
    
    # OUs hijas
    try {
        $children = Get-ADOrganizationalUnit -SearchBase $Source -SearchScope OneLevel -Filter *
        if ($children){
            foreach ($child in $children) {
                $childTarget = "OU=$($child.Name),$Target"
                Copy-OUTree $child.DistinguishedName $childTarget $CopyGPO $MoveObjs
            }
        }
    }
    catch {
        Write-Log "Error obteniendo hijas: $_" Error
    }
}
#endregion

#region GUI Functions
function Show-OUPicker {
    param(
        [string]$Title,
        [bool]$AllowNew = $false
    )
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(500,600)
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    
    # TreeView
    $tree = New-Object System.Windows.Forms.TreeView
    $tree.Location = New-Object System.Drawing.Point(10,10)
    $tree.Size = New-Object System.Drawing.Size(465,490)
    
    # Cargar dominio
    try {
        $domain = Get-ADDomain
        $root = New-Object System.Windows.Forms.TreeNode
        $root.Text = $domain.DNSRoot
        $root.Tag = $domain.DistinguishedName
        
        # Dummy para expansión
        $root.Nodes.Add('...') | Out-Null
        $tree.Nodes.Add($root) | Out-Null
        $root.Expand()
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error: $_",'Error','OK','Error')
        return $null
    }
    
    # Evento expansión
    $tree.Add_BeforeExpand({
        param($s,$e)
        $node = $e.Node
        
        if ($node.Nodes.Count -eq 1 -and $node.Nodes[0].Text -eq '...') {
            $node.Nodes.Clear()
            
            try {
                $ous = Get-ADOrganizationalUnit -SearchBase $node.Tag -SearchScope OneLevel -Filter * | Sort-Object Name
                
                foreach ($ou in $ous) {
                    $n = New-Object System.Windows.Forms.TreeNode
                    $n.Text = $ou.Name
                    $n.Tag = $ou.DistinguishedName
                    
                    # Ver si tiene hijas
                    if (Get-ADOrganizationalUnit -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue) {
                        $n.Nodes.Add('...') | Out-Null
                    }
                    
                    $node.Nodes.Add($n) | Out-Null
                }
            }
            catch {}
        }
    })
    
    $form.Controls.Add($tree)
    
    # Botones
    $y = 510
    
    if ($AllowNew) {
        $btnNew = New-Object System.Windows.Forms.Button
        $btnNew.Location = New-Object System.Drawing.Point(10,$y)
        $btnNew.Size = New-Object System.Drawing.Size(100,30)
        $btnNew.Text = 'Nueva OU'
        $btnNew.Add_Click({
            if (!$tree.SelectedNode) {
                [System.Windows.Forms.MessageBox]::Show('Seleccione OU padre','Info','OK','Information')
                return
            }
            
            $name = [Microsoft.VisualBasic.Interaction]::InputBox('Nombre:','Nueva OU','')
            if (!$name) { return }
            
            try {
                $parent = $tree.SelectedNode.Tag
                $new = New-ADOrganizationalUnit -Name $name -Path $parent -PassThru
                [System.Windows.Forms.MessageBox]::Show("Creada: $($new.DistinguishedName)",'Éxito','OK','Information')
                
                # Refrescar
                $tree.SelectedNode.Nodes.Clear()
                $tree.SelectedNode.Nodes.Add('...') | Out-Null
                $tree.SelectedNode.Collapse()
                $tree.SelectedNode.Expand()
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Error: $_",'Error','OK','Error')
            }
        })
        $form.Controls.Add($btnNew)
    }
    
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Location = New-Object System.Drawing.Point(265,$y)
    $btnOK.Size = New-Object System.Drawing.Size(100,30)
    $btnOK.Text = 'Seleccionar'
    $btnOK.DialogResult = 'OK'
    $form.Controls.Add($btnOK)
    
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(375,$y)
    $btnCancel.Size = New-Object System.Drawing.Size(100,30)
    $btnCancel.Text = 'Cancelar'
    $btnCancel.DialogResult = 'Cancel'
    $form.Controls.Add($btnCancel)
    
    $form.AcceptButton = $btnOK
    $form.CancelButton = $btnCancel
    
    if ($form.ShowDialog() -eq 'OK' -and $tree.SelectedNode) {
        return $tree.SelectedNode.Tag
    }
    
    return $null
}

function Start-Copy {
    param(
        [string]$Src,
        [string]$Dst,
        [bool]$GPO,
        [bool]$Move
    )
    
    Write-Log '=================================================='
    Write-Log 'COPIA DE JERARQUÍA DE OUs'
    Write-Log '=================================================='
    Write-Log "Origen:  $Src"
    Write-Log "Destino: $Dst"
    Write-Log "GPO:     $GPO"
    Write-Log "Mover:   $Move"
    Write-Log '=================================================='
    
    try {
        # Validar origen
        $null = Get-ADOrganizationalUnit $Src -ErrorAction Stop
        
        # Ejecutar
        Copy-OUTree $Src $Dst $GPO $Move
        
        Write-Log 'PROCESO COMPLETADO'
        [System.Windows.Forms.MessageBox]::Show('Copia completada','Éxito','OK','Information')
    }
    catch {
        Write-Log "ERROR: $_" Error
        [System.Windows.Forms.MessageBox]::Show("Error: $_",'Error','OK','Error')
    }
}
#endregion

#region Main GUI
function Show-Main {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Copia Espejo de OUs - Active Directory'
    $form.Size = New-Object System.Drawing.Size(800,650)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    
    # --- OU ORIGEN ---
    $grpSrc = New-Object System.Windows.Forms.GroupBox
    $grpSrc.Location = New-Object System.Drawing.Point(10,10)
    $grpSrc.Size = New-Object System.Drawing.Size(760,80)
    $grpSrc.Text = 'OU Origen'
    $form.Controls.Add($grpSrc)
    
    $txtSrc = New-Object System.Windows.Forms.TextBox
    $txtSrc.Location = New-Object System.Drawing.Point(10,25)
    $txtSrc.Size = New-Object System.Drawing.Size(620,20)
    $txtSrc.ReadOnly = $true
    $txtSrc.BackColor = [System.Drawing.Color]::White
    $grpSrc.Controls.Add($txtSrc)
    
    $btnSrc = New-Object System.Windows.Forms.Button
    $btnSrc.Location = New-Object System.Drawing.Point(640,23)
    $btnSrc.Size = New-Object System.Drawing.Size(110,25)
    $btnSrc.Text = 'Seleccionar...'
    $btnSrc.Add_Click({
        $sel = Show-OUPicker 'Seleccionar OU Origen'
        if ($sel) {
            $script:SourceOU = $sel
            $txtSrc.Text = $sel
        }
    })
    $grpSrc.Controls.Add($btnSrc)
    
    # --- OU DESTINO ---
    $grpDst = New-Object System.Windows.Forms.GroupBox
    $grpDst.Location = New-Object System.Drawing.Point(10,100)
    $grpDst.Size = New-Object System.Drawing.Size(760,80)
    $grpDst.Text = 'OU Destino'
    $form.Controls.Add($grpDst)
    
    $txtDst = New-Object System.Windows.Forms.TextBox
    $txtDst.Location = New-Object System.Drawing.Point(10,25)
    $txtDst.Size = New-Object System.Drawing.Size(620,20)
    $txtDst.ReadOnly = $true
    $txtDst.BackColor = [System.Drawing.Color]::White
    $grpDst.Controls.Add($txtDst)
    
    $btnDst = New-Object System.Windows.Forms.Button
    $btnDst.Location = New-Object System.Drawing.Point(640,23)
    $btnDst.Size = New-Object System.Drawing.Size(110,25)
    $btnDst.Text = 'Seleccionar...'
    $btnDst.Add_Click({
        $sel = Show-OUPicker 'Seleccionar OU Destino' -AllowNew $true
        if ($sel) {
            $script:TargetOU = $sel
            $txtDst.Text = $sel
        }
    })
    $grpDst.Controls.Add($btnDst)
    
    # --- OPCIONES ---
    $grpOpt = New-Object System.Windows.Forms.GroupBox
    $grpOpt.Location = New-Object System.Drawing.Point(10,190)
    $grpOpt.Size = New-Object System.Drawing.Size(760,60)
    $grpOpt.Text = 'Opciones'
    $form.Controls.Add($grpOpt)
    
    $chkGPO = New-Object System.Windows.Forms.CheckBox
    $chkGPO.Location = New-Object System.Drawing.Point(20,25)
    $chkGPO.Size = New-Object System.Drawing.Size(200,20)
    $chkGPO.Text = 'Copiar vínculos de GPO'
    $grpOpt.Controls.Add($chkGPO)
    
    $chkMove = New-Object System.Windows.Forms.CheckBox
    $chkMove.Location = New-Object System.Drawing.Point(250,25)
    $chkMove.Size = New-Object System.Drawing.Size(200,20)
    $chkMove.Text = 'Mover objetos'
    $grpOpt.Controls.Add($chkMove)
    
    # --- LOG ---
    $grpLog = New-Object System.Windows.Forms.GroupBox
    $grpLog.Location = New-Object System.Drawing.Point(10,260)
    $grpLog.Size = New-Object System.Drawing.Size(760,300)
    $grpLog.Text = 'Log en Tiempo Real'
    $form.Controls.Add($grpLog)
    
    $lblPath = New-Object System.Windows.Forms.Label
    $lblPath.Location = New-Object System.Drawing.Point(10,18)
    $lblPath.Size = New-Object System.Drawing.Size(740,15)
    $lblPath.Text = "Archivo: $($script:LogFile)"
    $lblPath.Font = New-Object System.Drawing.Font('Arial',7)
    $lblPath.ForeColor = [System.Drawing.Color]::Gray
    $grpLog.Controls.Add($lblPath)
    
    $script:LogBox = New-Object System.Windows.Forms.TextBox
    $script:LogBox.Location = New-Object System.Drawing.Point(10,35)
    $script:LogBox.Size = New-Object System.Drawing.Size(740,255)
    $script:LogBox.Multiline = $true
    $script:LogBox.ScrollBars = 'Vertical'
    $script:LogBox.ReadOnly = $true
    $script:LogBox.BackColor = [System.Drawing.Color]::Black
    $script:LogBox.ForeColor = [System.Drawing.Color]::Lime
    $script:LogBox.Font = New-Object System.Drawing.Font('Consolas',9)
    $grpLog.Controls.Add($script:LogBox)
    
    # --- BOTONES ---
    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Location = New-Object System.Drawing.Point(560,570)
    $btnRun.Size = New-Object System.Drawing.Size(100,35)
    $btnRun.Text = 'Ejecutar'
    $btnRun.Add_Click({
        if (!$script:SourceOU) {
            [System.Windows.Forms.MessageBox]::Show('Seleccione OU origen','Validación','OK','Warning')
            return
        }
        
        if (!$script:TargetOU) {
            [System.Windows.Forms.MessageBox]::Show('Seleccione OU destino','Validación','OK','Warning')
            return
        }
        
        $r = [System.Windows.Forms.MessageBox]::Show('¿Iniciar copia?','Confirmar','YesNo','Question')
        if ($r -ne 'Yes') { return }
        
        $btnRun.Enabled = $false
        $btnSrc.Enabled = $false
        $btnDst.Enabled = $false
        
        Start-Copy $script:SourceOU $script:TargetOU $chkGPO.Checked $chkMove.Checked
        
        $btnRun.Enabled = $true
        $btnSrc.Enabled = $true
        $btnDst.Enabled = $true
    })
    $form.Controls.Add($btnRun)
    
    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Location = New-Object System.Drawing.Point(670,570)
    $btnExit.Size = New-Object System.Drawing.Size(100,35)
    $btnExit.Text = 'Cerrar'
    $btnExit.Add_Click({ $form.Close() })
    $form.Controls.Add($btnExit)
    
    $form.ShowDialog() | Out-Null
}
#endregion

#region Main
Initialize-Log
Write-Log 'Sistema iniciado'
Write-Log "Log: $($script:LogFile)"

if (!(Get-Module ActiveDirectory)) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log 'Módulo AD cargado'
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error cargando módulo AD: $_",'Error','OK','Error')
        exit
    }
}

Show-Main
#endregion
