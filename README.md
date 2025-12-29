# Raven Redact

> [!NOTE]
> Our free software is licensed under the [BSD-3-Clause license](https://ravendevteam.org/files/BSD-3-Clause.txt). By using our software, you acknowledge and agree to the terms of the license.

Destroy files securely.

When you 'delete' a file, it does not actually delete it. Instead, it marks that space as free so that new data can overwrite it later. If that space has not been overwritten, the old data is still recoverable. Redact takes it a step further, using the Redact Algorithm, to securely shred files, making them realistically unrecoverable*.

* While the Redact Algorithm is designed to significantly reduce the risk of data recovery, absolute irrecoverability cannot be guaranteed in all environments. Recovery may still be possible under certain conditions, including but not limited to solid-state drives (SSD) with wear-leveling, copy-on-write filesystems, filesystem journaling, system-level caching, backups, snapshots, or advanced hardware forensic techniques. The algorithm provides best-effort logical destruction for per-file shredding, not physical media sanitization, which is beyond the scope of a desktop application.

Made for Windows 11.

## Possible Data Recovery Scenarios

A list of scenarios in which data recovery may still be possible after redaction, and the threat assessment of each:

|Scenario                   |Threat Level    |Notes                                                       |
|---------------------------|----------------|------------------------------------------------------------|
|Backups                    |**High**        |Most common real-world failure mode.                        |
|SSD wear-leveling          |**Moderate**    |Common, but recovery is inconsistent and hardware-dependent.|
|Snapshots / shadow copies  |**Moderate**    |Depends on configuration.                                   |
|Filesystem journaling      |**Low/Moderate**|Requires timing, access, and incomplete overwrite.          |
|Copy-on-write filesystems  |**Low**         |Mostly irrelevant on NTFS.                                  |
|System-level caching       |**Low**         |Narrow window, volatile.                                    |
|Advanced hardware forensics|**Very low**    |Nation-state / lab-level only.                              |

## Installation
You can download Redact [here](https://ravendevteam.org/explore#redact).

To compile from source, make sure you have Python 3.12.4, and Nuitka. Install the necessary dependencies from `requirements.txt`, then run `build.bat`.

## Authors & Contributors

- [Raven Development Team](https://ravendevteam.org/)
- [Icons by Icons8](https://icons8.com/)
- [urbanawakening](https://github.com/urbanawakening)