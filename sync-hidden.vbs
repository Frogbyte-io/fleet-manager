' Runs the given command line completely hidden (no console window flash).
' Used by the agents-registry-sync scheduled task to invoke sync.ps1 silently.
Set objShell = CreateObject("WScript.Shell")
objShell.Run WScript.Arguments(0), 0, True
