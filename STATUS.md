# Project Status

**Maturity: Beta**

## Tested

- Windows with PowerShell 7.6.6.
- RSAT ActiveDirectory and GroupPolicy modules loaded directly in PowerShell 7.
- A lab AD domain with 36 GPOs; the audit produced 402 ACL snapshot rows and matching CSV/HTML reports.
- The report data included trustee comparisons and default GPO ACLs. No matching Security events were present in the tested 30-day window, so event parsing against positive event samples remains unverified.

## Known limitations

- Runtime has not been benchmarked on large domains (for example, 30 domain controllers and 80-85 GPOs).
- The user must be able to read the Security log on every discovered DC and reach AD, SYSVOL, and remote event logs through the environment's configured protocols/firewall.
- Event collection depends on the required audit subcategories and SACLs having been configured before the events occurred; the script does not configure them.
- Only events that match a known GPO are included. Event 4662 is additionally limited to `groupPolicyContainer` ObjectType and `WRITE_DAC`.
- GPC permission levels and GPT NTFS rights are different models. Unmatched-trustee and inheritance signals require review and do not establish effective access by themselves; check nested group membership and NTFS/Share intersections.
- The HTML report contains the same sensitive identity and policy data as the CSV. Store and share both securely.

## Roadmap

- Add configurable lookback window and bounded throttle parameters.
- Add repeatable tests with synthetic events and ACL fixtures.
- Validate Event 4662 XPath encodings and event parsing against captured, sanitized positive samples from multiple supported Windows Server versions.
- Benchmark collection against larger AD environments and tune progress/detail reporting.
- Consider machine-readable JSON output while preserving the current CSV schema.
