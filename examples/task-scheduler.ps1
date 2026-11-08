# Windows: run `pathmap trace` every 5 minutes with Task Scheduler (tracert is built in). Run once in PowerShell.
$action  = New-ScheduledTaskAction -Execute "pathmap" -Argument "trace 1.1.1.1 example.org --data C:\pathmap-data"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "pathmap" -Action $action -Trigger $trigger
