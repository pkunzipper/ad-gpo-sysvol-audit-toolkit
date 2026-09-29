# AD GPO/SYSVOL Audit Toolkit

A read-only PowerShell toolkit for reviewing Group Policy permissions in Active Directory and SYSVOL.

![PowerShell 7.0+](https://img.shields.io/badge/PowerShell-7.0%2B-5391FE?logo=powershell&logoColor=white) ![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## What this does

- Captures GPC permissions returned by `Get-GPPermission` and NTFS ACLs on each GPO's SYSVOL GPT.
- Compares trustee SIDs across the two permission models and reports unmatched trustees or inheritance signals for human review.
- Collects matching Security events (4662 `WRITE_DAC`, 4670, and 5136) from domain controllers for the previous 30 days.
- Writes a timestamped CSV and a self-contained HTML dashboard with summaries, charts, search, and pagination.

The script only reads AD, SYSVOL ACLs, and Security event logs. It does not change GPOs, directory objects, permissions, auditing policy, or group membership.

## Prerequisites

- Windows and PowerShell 7.0 or later.
- RSAT ActiveDirectory and GroupPolicy modules installed.
- Read access to the Security event log on every discovered domain controller.
- Network connectivity to the domain controllers for AD/GPO queries, SYSVOL access, and remote Security log reads. Required protocols depend on the host firewall and AD configuration.
- Write access to the current directory for the generated reports.

The script loads the RSAT modules directly in PowerShell 7 with `-SkipEditionCheck`. It does not use the Windows PowerShell compatibility remoting layer, because deserialization can discard trustee SID data needed by the comparison.

## Usage

Run from the directory where you want the reports written:

```powershell
pwsh -NoProfile -File .\scripts\Invoke-AdGpoSysvolAudit.ps1
```

The script currently has no parameters. The Security event lookback is fixed at 30 days; GPO ACL reads use a throttle of 5 and domain-controller event reads use a throttle of 3.

On completion, the current directory contains files similar to:

```text
gpo-sysvol-audit-20260929-120000.csv
gpo-sysvol-audit-20260929-120000.html
```

The HTML report is offline and embeds the collected rows. Treat both reports as sensitive because they contain domain, policy, permission, and identity information.

## Reading the output

The CSV retains one row shape for ACL snapshots and one for matching Security events. Fields that do not apply to a row type are blank.

| Column | Meaning |
| --- | --- |
| `CollectedAtUtc` | UTC collection timestamp. |
| `RecordType` | `ACL snapshot` or `Security event`. |
| `DomainController` | Snapshot DC for ACL rows; event source DC for event rows. |
| `GpoDisplayName` | GPO display name. |
| `GpoGuid` | GPO GUID. |
| `GpcDistinguishedName` | AD distinguished name of the GPC. |
| `GptPath` | SYSVOL path of the GPT. |
| `Source` | `GPC / Get-GPPermission`, `GPT / SYSVOL NTFS`, or `Windows Security`. |
| `Principal` | Trustee name, when applicable. |
| `PrincipalKey` | SID used for comparison, or normalized fallback text if SID translation fails. |
| `Permission` | GPC permission level or GPT file-system rights. These models are not one-to-one equivalents. |
| `AccessControlType` | NTFS `Allow` or `Deny`; blank for GPC and event rows. |
| `IsInherited` | Whether the permission/ACE is inherited. |
| `InheritanceProtected` | Whether the GPT DACL is protected from parent inheritance. |
| `ComparisonSignal` | Trustee-side or inheritance signal for review; not an automatic finding. |
| `EventId` | Matching Security event ID. |
| `EventTimeUtc` | Event timestamp in UTC. |
| `Actor` | Event subject account. |
| `Attribute` | LDAP attribute associated with Event 5136. |
| `Value` | Attribute value associated with Event 5136. |
| `OperationType` | Event operation type. |
| `CorrelationId` | Event correlation ID, when present. |
| `RecordId` | Security log record ID. |
| `AccessMask` | Event access mask; Event 4662 is retained only when `WRITE_DAC` is set. |
| `ProcessName` | Process name when present in the event. |
| `OldSecurityDescriptor` | Previous security descriptor when present. |
| `NewSecurityDescriptor` | New security descriptor when present. |

The HTML dashboard summarizes GPOs scanned, ACL rows, matching events, and unmatched trustees. It charts events by ID, ACL rows by source, and events by DC; its filterable, searchable table is paginated. An unmatched trustee is a triage signal only: validate group membership, ACE scope/inheritance, and effective NTFS **and** Share rights before drawing conclusions.

## Disclaimer

This software is provided without warranty. Test it in a non-production environment and review the script and resulting reports before any production use. Although the toolkit is designed not to modify AD, GPOs, SYSVOL permissions, or audit policy, you are responsible for validating its behavior and protecting its output.

## Extended methodology

- [Italian guide: GPO/SYSVOL permission audit](https://www.mgworkplace.it/it/field-guides/active-directory-gpo-sysvol-acl-security-assessment)
- [English guide: GPO/SYSVOL permission audit](https://www.mgworkplace.it/en/field-guides/active-directory-gpo-sysvol-acl-security-assessment)
