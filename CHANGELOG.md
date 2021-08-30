# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support printing an entire single database entry

### Changed

- Catch CTRL-C during questionnaire when submitting data
- Use `readline` so you can use backspace when interactively answering questions
- Gracefully handle missing hashcat binary during questionnaire

### Fixed

- "Higher is better" was applied twice when creating the stats
- Prevent exception in `db stats` if there is no largest cluster

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
