; Custom NSIS installer script for context menu integration

!macro customInstall
  ; Add "Open with Null IDE" to file context menu
  WriteRegStr SHCTX "Software\Classes\*\shell\NullIDE" "" "Open with Null IDE"
  WriteRegStr SHCTX "Software\Classes\*\shell\NullIDE" "Icon" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  WriteRegStr SHCTX "Software\Classes\*\shell\NullIDE\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%1"'
  
  ; Add "Open with Null IDE" to folder context menu  
  WriteRegStr SHCTX "Software\Classes\Directory\shell\NullIDE" "" "Open with Null IDE"
  WriteRegStr SHCTX "Software\Classes\Directory\shell\NullIDE" "Icon" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  WriteRegStr SHCTX "Software\Classes\Directory\shell\NullIDE\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%1"'
  
  ; Add "Open Null IDE here" to folder background context menu
  WriteRegStr SHCTX "Software\Classes\Directory\Background\shell\NullIDE" "" "Open Null IDE here"
  WriteRegStr SHCTX "Software\Classes\Directory\Background\shell\NullIDE" "Icon" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  WriteRegStr SHCTX "Software\Classes\Directory\Background\shell\NullIDE\command" "" '"$INSTDIR\${APP_EXECUTABLE_FILENAME}" "%V"'
!macroend

!macro customUnInstall
  ; Remove context menu entries
  DeleteRegKey SHCTX "Software\Classes\*\shell\NullIDE"
  DeleteRegKey SHCTX "Software\Classes\Directory\shell\NullIDE"
  DeleteRegKey SHCTX "Software\Classes\Directory\Background\shell\NullIDE"
!macroend
