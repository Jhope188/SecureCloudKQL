
// Show all connections from outside trustedlocations and working hours


let TrustedIPs = dynamic(["174.99.137.2", "184.80.210.162", "184.80.210.157", "174.99.131.218", "184.80.210.146", "184.80.210.153", "40.114.38.227"]);

WVDConnections
| where TimeGenerated > ago(60d)
| extend hour = datetime_part("hour", TimeGenerated)
| extend dayofmonth = datetime_part("Day", TimeGenerated)
| extend dayofweek = toint(format_timespan(dayofweek(TimeGenerated), 'd'))
| extend dayname = case (dayofweek == 0, "Sunday",
    dayofweek == 1, "Monday",
    dayofweek == 2, "Tuesday",
    dayofweek == 3, "Wednesday",
    dayofweek == 4, "Thursday",
    dayofweek == 5, "Firday",
    dayofweek == 6, "Saturday",
    "unknown")
| where (hourofday(TimeGenerated) !between (13 .. 22) and dayofweek != 0 and dayofweek != 6)
    or (dayofweek == 0 or dayofweek == 6)
    and (hourofday(TimeGenerated) !between (13 .. 16))
| where State == "Connected"
| where not(ClientSideIPAddress in (TrustedIPs))
| project UserName, SessionHostName, TimeGenerated, ClientOS, ClientSideIPAddress




// Show all connections even from trusted locations outside working hours
WVDConnections
| where TimeGenerated > ago(60d)
| extend hour = datetime_part("hour", TimeGenerated)
| extend dayofmonth = datetime_part("Day", TimeGenerated)
| extend dayofweek = toint(format_timespan(dayofweek(TimeGenerated), 'd'))
| extend dayname = case (dayofweek == 0, "Sunday",
    dayofweek == 1, "Monday",
    dayofweek == 2, "Tuesday",
    dayofweek == 3, "Wednesday",
    dayofweek == 4, "Thursday",
    dayofweek == 5, "Firday",
    dayofweek == 6, "Saturday",
    "unknown")
| where (hourofday(TimeGenerated) !between (13 .. 22) and dayofweek != 0 and dayofweek != 6)
    or (dayofweek == 0 or dayofweek == 6)
    and (hourofday(TimeGenerated) !between (13 .. 16))
| where State == "Connected"
| project UserName, SessionHostName, TimeGenerated