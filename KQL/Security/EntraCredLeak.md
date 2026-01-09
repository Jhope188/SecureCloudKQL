https://www.reddit.com/r/sysadmin/comments/1k2pmkz/new_entra_leaked_credentials_no_breach_on_hibp_etc/



CloudAppEvents
 | where ActionType has "Add service principal"
 | where ObjectName contains "MACE"
 | project TenantId, ObjectName, Timestamp
