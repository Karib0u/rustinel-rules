# Atomic test - rule d6adbfee-548b-4def-9e49-8e6940251957
#   "WMI Event Subscription Persistence"  (wmi_event)
#
# Registers a complete permanent WMI subscription - __EventFilter,
# CommandLineEventConsumer, __FilterToConsumerBinding - and then removes all
# three. This is the rule's only honest test: it keys on the touched class name
# appearing in the WMI-Activity Operation text, and nobody had shown that the
# trace events the engine subscribes to (IDs 1, 2, 11, 12, 14-17, 22-24) carry
# it. The rule was shipping in Windows Essential unproven; one CI run with this
# test settles whether it fires or belongs in preview/.
#
# The subscription is inert by construction: the filter watches __InstanceCreationEvent
# for a WMI class that never gets an instance, and the consumer would run
# `cmd.exe /c exit 0` if it somehow did. Everything is removed in `finally`, so a
# failure part-way through does not leave persistence behind.
#
# Marked allow_failure in the manifest until a run proves the Operation text
# carries the class name.
$ErrorActionPreference = 'Stop'
$ns = 'root\subscription'
$name = 'RustinelAtomicTest'

$filter = $null
$consumer = $null
$binding = $null
try {
    $filter = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{
        Name           = $name
        EventNamespace = 'root\cimv2'
        QueryLanguage  = 'WQL'
        # Win32_LocalTime instances are never created, only modified, so this
        # filter can never match.
        Query          = "SELECT * FROM __InstanceCreationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"
    }

    $consumer = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{
        Name                = $name
        CommandLineTemplate = 'cmd.exe /c exit 0'
    }

    $binding = Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{
        Filter   = $filter
        Consumer = $consumer
    }

    Start-Sleep -Seconds 2
} finally {
    foreach ($instance in @($binding, $consumer, $filter)) {
        if ($instance) {
            try { $instance.Delete() } catch { Write-Host "cleanup failed: $_" }
        }
    }
}
exit 0
