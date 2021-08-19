# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
