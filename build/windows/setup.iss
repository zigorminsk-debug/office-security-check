; Script Inno Setup — установщик «Аудит защиты» (Office Security Check) для Windows.
; Собирается командой ISCC.exe build\windows\setup.iss (см. .github/workflows/build.yml).

#define MyAppName "Аудит защиты"
#define MyAppNameEn "Office Security Check"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Office Security Check"
#define MyAppExeName "SecurityAudit.exe"

[Setup]
AppId={{6E2D5A4B-9F31-4C57-8B0A-2D9C7E4F1A30}
AppName={#MyAppName}
AppVerName={#MyAppName} {#MyAppVersion} ({#MyAppNameEn})
AppPublisher={#MyAppPublisher}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\OfficeSecurityCheck
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\..\dist
OutputBaseFilename=Setup-Audit-Zashchity
SetupIconFile=app.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64
PrivilegesRequired=admin
UninstallDisplayName={#MyAppName}

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\..\dist\SecurityAudit.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\SecurityAuditCLI.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{#MyAppName} — командная строка"; Filename: "{app}\SecurityAuditCLI.exe"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent
