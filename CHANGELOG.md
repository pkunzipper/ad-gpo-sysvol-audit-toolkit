# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-29

### Added

- Read-only GPC permission and SYSVOL GPT NTFS ACL inventory.
- Trustee SID comparison and inheritance review signals.
- Collection of matching Security events 4662 (`WRITE_DAC`), 4670, and 5136 from domain controllers for the previous 30 days.
- Timestamped CSV output and a self-contained HTML dashboard.
- Bounded parallel collection and progress reporting.
- PowerShell 7+ RSAT loading and bilingual methodology links.
