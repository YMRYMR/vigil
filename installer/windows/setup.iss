; Vigil — Inno Setup installer script
;
; Build from the repo root:
;   iscc /DMyAppVersion=1.0.0 installer\windows\setup.iss
;
; In CI the version is injected from the git tag.

#ifndef MyAppVersion
  #define MyAppVersion "0.0.0-dev"
#endif

#define MyAppName      "Vigil"
#define MyAppPublisher "Vigil Contributors"
#define MyAppURL       "https://github.com/YOUR_USERNAME/vigil"
#define MyAppExeName   "vigil.exe"

[Setup]
; Unique application ID — do not change after first release.
AppId={{3B7E2F1A-C4D5-4E6F-A7B8-9C0D1E2F3A4B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases

; Install to Program Files by default; allow per-user install without elevation.
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequiredOverridesAllowed=dialog

; Installer appearance
WizardStyle=modern
SetupIconFile=..\..\assets\vigil_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

; Output
OutputDir=output
OutputBaseFilename=Vigil-Setup-{#MyAppVersion}-x86_64

; Compression
Compression=lzma2/ultra64
SolidCompression=yes

; Minimum Windows version: Windows 10
MinVersion=10.0

LicenseFile=..\..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; \
  Description: "{cm:CreateDesktopIcon}"; \
  GroupDescription: "{cm:AdditionalIcons}"; \
  Flags: unchecked

[Files]
; The binary is staged next to setup.iss before ISCC runs (see release.yml).
Source: "{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}";           Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}";     Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Offer to launch Vigil immediately after installation.
; Vigil enables autostart on its own first run — no registry entry needed here.
Filename: "{app}\{#MyAppExeName}"; \
  Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; \
  Flags: nowait postinstall skipifsilent
