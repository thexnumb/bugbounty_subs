# bugbounty_subs
in this repo I'm going to gather all subdomains that is belong to the company I'm working on it
A comprehensive tool for automating subdomain enumeration across multiple bug bounty programs using various techniques and sources. Includes GitHub Actions integration for automatic scheduled scanning.

## Features

- **Multiple Data Sources**: Collects subdomains from various sources including:
  - AbuseIPDB WHOIS information
  - Subdomain.center API
  - Subfinder
  - Chaos
  - Certificate Transparency logs (crt.sh)
  - GetAllUrls (gau)
  - Wayback Machine

- **Organized Structure**: Automatically organizes results by program and domain
- **Deduplication**: Ensures unique subdomains in the output files
- **Filtering**: Removes invalid and wildcard subdomains
- **Automation**: Runs weekly via GitHub Actions to discover new subdomains automatically
