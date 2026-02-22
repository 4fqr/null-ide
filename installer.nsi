!include "MUI2.nsh"

; Installer script for Null IDE with context menu integration

!define PRODUCT_NAME "Null IDE"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "NullSec"
!define PRODUCT_WEB_SITE "https://github.com/nullsec"

; MUI Settings
!define MUI_ABORTWARNING
!define MUI_ICON "null-ide.ico"
!define MUI_UNICON "null-ide.ico"

; Welcome page
!insertmacro MUI_PAGE_WELCOME
; Directory page
!insertmacro MUI_PAGE_DIRECTORY
; Instfiles page
!insertmacro MUI_PAGE_INSTFILES
; Finish page
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_INSTFILES

; Language files
!insertmacro MUI_LANGUAGE "English"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "Null-IDE-Installer.exe"
InstallDir "$PROGRAMFILES\Null IDE"
InstallDirRegKey HKLM "Software\NullSec\NullIDE" "Install_Dir"
ShowInstDetails show
ShowUnInstDetails show

Section "MainSection" SEC01
  SetOutPath "$INSTDIR"
  SetOverwrite ifnewer
  
  ; Your application files will be added here by electron-builder
  File /r "dist\*.*"
  File "null-ide.ico"
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
  
  ; Registry entries
  WriteRegStr HKLM "Software\NullSec\NullIDE" "Install_Dir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NullIDE" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NullIDE" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NullIDE" "DisplayIcon" "$INSTDIR\null-ide.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NullIDE" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NullIDE" "DisplayVersion" "${PRODUCT_VERSION}"
  
  ; Create desktop shortcut
  CreateShortCut "$DESKTOP\Null IDE.lnk" "$INSTDIR\Null IDE.exe" "" "$INSTDIR\null-ide.ico"
  
  ; Create start menu shortcuts
  CreateDirectory "$SMPROGRAMS\Null IDE"
  CreateShortCut "$SMPROGRAMS\Null IDE\Null IDE.lnk" "$INSTDIR\Null IDE.exe" "" "$INSTDIR\null-ide.ico"
  CreateShortCut "$SMPROGRAMS\Null IDE\Uninstall.lnk" "$INSTDIR\uninstall.exe"
  
  ; Add context menu for files
  WriteRegStr HKCR "*\shell\OpenWithNullIDE" "" "Open with Null IDE"
  WriteRegStr HKCR "*\shell\OpenWithNullIDE" "Icon" "$INSTDIR\null-ide.ico"
  WriteRegStr HKCR "*\shell\OpenWithNullIDE\command" "" '"$INSTDIR\Null IDE.exe" "%1"'
  
  ; Add context menu for folders
  WriteRegStr HKCR "Directory\shell\OpenWithNullIDE" "" "Open with Null IDE"
  WriteRegStr HKCR "Directory\shell\OpenWithNullIDE" "Icon" "$INSTDIR\null-ide.ico"
  WriteRegStr HKCR "Directory\shell\OpenWithNullIDE\command" "" '"$INSTDIR\Null IDE.exe" "%1"'
  
  ; Add context menu for directory background (inside folder)
  WriteRegStr HKCR "Directory\Background\shell\OpenWithNullIDE" "" "Open Null IDE here"
  WriteRegStr HKCR "Directory\Background\shell\OpenWithNullIDE" "Icon" "$INSTDIR\null-ide.ico"
  WriteRegStr HKCR "Directory\Background\shell\OpenWithNullIDE\command" "" '"$INSTDIR\Null IDE.exe" "%V"'
  
  ; Add to PATH (optional)
  EnVar::SetHKLM
  EnVar::AddValue "PATH" "$INSTDIR"
  
SectionEnd

Section "Uninstall"
  ; Remove files
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\null-ide.ico"
  RMDir /r "$INSTDIR"
  
  ; Remove shortcuts
  Delete "$DESKTOP\Null IDE.lnk"
  Delete "$SMPROGRAMS\Null IDE\Null IDE.lnk"
  Delete "$SMPROGRAMS\Null IDE\Uninstall.lnk"
  RMDir "$SMPROGRAMS\Null IDE"
  
  ; Remove registry entries
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NullIDE"
  DeleteRegKey HKLM "Software\NullSec\NullIDE"
  
  ; Remove context menu entries
  DeleteRegKey HKCR "*\shell\OpenWithNullIDE"
  DeleteRegKey HKCR "Directory\shell\OpenWithNullIDE"
  DeleteRegKey HKCR "Directory\Background\shell\OpenWithNullIDE"
  
  ; Remove from PATH
  EnVar::SetHKLM
  EnVar::DeleteValue "PATH" "$INSTDIR"
  
SectionEnd
