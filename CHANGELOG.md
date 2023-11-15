# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Progress bar when creating BloodHound relationships
- Add option for raw database query
- Expose `--include-disabled` and `--include-computer-accounts`
- Show cracked computer accounts in analytics report

### Changed

- Changed the order of the key quantities in the analytics report to a more
  sensible one
- Sort clusters in details section of analytics report by size
- Change definition of a percentile from "less than" to "less than or equal"

### Fixed

- Avoid printing passwords in log messages

## [0.1.5] - 2022-08-30

### Added

- A list of all found credentials can be included in the report with degree
  of detail >= 4
- Support for encryption option in connections to the neo4j database

### Fixed

- Percentage of 'user = password' was relative to cracked passwords, not all
  accounts

## [0.1.4] - 2022-06-27

### Added

- Support `xlsx` format
- Add parameter to change the minimum password length in the context of
  identifying short passwords
- Include optional lookup in HIBP database in the detailed report
- Add parameter `--keep-tempdir`
- Add interactions with BloodHound: as a filter (#11) and adding
  "SamePassword" edges (#7)

### Changed

- Performance improvement when creating the report
- Require Python 3.6 or greater
- Use MD4 implementation in pure Python because the openssl provider for
  `hashlib` may not support legacy algorithms
- Improve error handling

## [0.1.3] - 2021-11-12

### Added

- Support printing an entire single database entry
- Support deleting single database entries
- Support generating stats of reports without submitting them to the
  database first
- Support HTML format in `analytics` subcommand
- Add the `--degree-of-detail` switch in `analytics` subcommand
- Add clusters to detailed report

### Changed

- Catch CTRL-C during questionnaire when submitting data
- Use `readline` so you can use backspace when interactively answering questions
- Gracefully handle missing hashcat binary during questionnaire
- Improve formatting of output of `db query`
- User must now confirm before deleting an entry
- Check hashcat's return code
- Replace "empty" with "blank" in top 10 passwords list
- Automatically remove computer accounts (end with $) or accounts that are
  marked as inactive in the pwdump file like `secretsdump -user-status` does
  it
- Ignore hashcat warnings when retrieving usernames (#4)
- Check existence of critical files before running `ntlm` subcommand
- Handle `$HEX[]` passwords
- Improve the way information is presented in the reports

### Fixed

- "Higher is better" was applied twice when creating the stats
- Prevent exception in `db stats` if there is no largest cluster
- Prevent exception when creating a report and no top passwords exist
- Fix LM detection when cracking several hash files at once
- Handle files that contain single malformed lines

### Added

- Show information about the number of entries when creating the stats

## [0.1.2] - 2021-08-19

### Added
- Add usernames to wordlist

### Changed
- Count nonunique passwords instead of unique passwords, since we want to
  minimize most metrics
- Use more ordered dictionaries to get more consistency when using Python
  3.5
- Remove filtered accounts also from hashes
- Skip LM hash cracking if they're all empty

### Fixed
- Detection of the empty LM hash
- Percentile computation on average password length (because more is better)
- Formatting of percentages

### Removed
- Attribute "empty_password" from analytics output
