#!/usr/bin/env python3
"""SIGMA rule validator for Muninn CI and local development.

Usage:
    python3 validate_sigma.py --check-yaml /tmp/changed_rules.txt
    python3 validate_sigma.py --check-fields /tmp/changed_rules.txt
    python3 validate_sigma.py --check-duplicates
    python3 validate_sigma.py --all sigma_rules/
"""

import argparse
import os
import re
import sys
from pathlib import Path

import yaml

UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'logsource', 'detection', 'level']
VALID_LEVELS = {'critical', 'high', 'medium', 'low', 'informational'}
VALID_STATUSES = {'stable', 'test', 'experimental', 'deprecated', 'unsupported'}


def read_file_list(path):
    """Read a file containing one rule path per line."""
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and line.strip().endswith('.yml')]


def find_all_rules(directory):
    """Find all .yml files in a directory tree."""
    return sorted(Path(directory).rglob('*.yml'))


def check_yaml(files):
    """Validate YAML syntax for each file."""
    errors = 0
    for filepath in files:
        if not os.path.isfile(filepath):
            continue
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                print(f'ERROR: {filepath} — not a valid SIGMA rule (not a YAML mapping)')
                errors += 1
        except yaml.YAMLError as e:
            print(f'ERROR: {filepath} — YAML parse error: {e}')
            errors += 1
    if errors:
        print(f'\n{errors} rule(s) have YAML syntax errors')
    else:
        print(f'All {len(files)} YAML files are syntactically valid')
    return errors


def check_fields(files):
    """Validate required fields and data quality."""
    errors = 0
    warnings = 0
    for filepath in files:
        if not os.path.isfile(filepath):
            continue
        try:
            with open(filepath) as f:
                rule = yaml.safe_load(f)
        except yaml.YAMLError:
            continue  # YAML errors caught by check_yaml

        if not isinstance(rule, dict):
            continue

        # Check required fields
        missing = [f for f in REQUIRED_FIELDS if f not in rule]
        if missing:
            print(f'ERROR: {filepath} — missing required fields: {missing}')
            errors += 1
            continue

        # Check detection has condition
        detection = rule.get('detection', {})
        if isinstance(detection, dict) and 'condition' not in detection:
            print(f'ERROR: {filepath} — detection section missing "condition"')
            errors += 1

        # Check UUID format
        rule_id = str(rule.get('id', ''))
        if not UUID_RE.match(rule_id):
            print(f'ERROR: {filepath} — invalid UUID: {rule_id}')
            errors += 1

        # Check level
        level = rule.get('level', '')
        if level not in VALID_LEVELS:
            print(f'ERROR: {filepath} — invalid level: {level} (must be one of {VALID_LEVELS})')
            errors += 1

        # Check status
        status = rule.get('status', '')
        if status not in VALID_STATUSES:
            print(f'ERROR: {filepath} — invalid status: {status} (must be one of {VALID_STATUSES})')
            errors += 1

        # Warning: no MITRE ATT&CK tags
        tags = rule.get('tags', []) or []
        has_attack = any(str(t).startswith('attack.t') for t in tags)
        if not has_attack:
            print(f'WARNING: {filepath} — no MITRE ATT&CK technique tag (attack.tXXXX)')
            warnings += 1

        # Warning: no references
        refs = rule.get('references', []) or []
        if not refs:
            print(f'WARNING: {filepath} — no references provided')
            warnings += 1

        # Warning: no false positives
        fps = rule.get('falsepositives', []) or []
        if not fps:
            print(f'WARNING: {filepath} — no false positives documented')
            warnings += 1

    if errors:
        print(f'\n{errors} error(s), {warnings} warning(s)')
    else:
        print(f'All rules pass field validation ({warnings} warning(s))')
    return errors


def check_duplicates(directory='sigma_rules'):
    """Check for duplicate UUIDs across all rules."""
    seen = {}
    duplicates = 0
    for filepath in find_all_rules(directory):
        try:
            with open(filepath) as f:
                rule = yaml.safe_load(f)
            if isinstance(rule, dict) and 'id' in rule:
                rule_id = str(rule['id'])
                if rule_id in seen:
                    print(f'ERROR: Duplicate UUID {rule_id}')
                    print(f'  → {seen[rule_id]}')
                    print(f'  → {filepath}')
                    duplicates += 1
                else:
                    seen[rule_id] = filepath
        except (yaml.YAMLError, OSError):
            continue

    if duplicates:
        print(f'\n{duplicates} duplicate UUID(s) found')
    else:
        print(f'No duplicate UUIDs among {len(seen)} rules')
    return duplicates


def main():
    parser = argparse.ArgumentParser(description='SIGMA rule validator for Muninn')
    parser.add_argument('--check-yaml', metavar='FILE_LIST', help='Validate YAML syntax')
    parser.add_argument('--check-fields', metavar='FILE_LIST', help='Validate required fields')
    parser.add_argument('--check-duplicates', action='store_true', help='Check for duplicate UUIDs')
    parser.add_argument('--all', metavar='DIRECTORY', help='Run all checks on a directory')
    args = parser.parse_args()

    errors = 0

    if args.all:
        files = [str(p) for p in find_all_rules(args.all)]
        print(f'Validating {len(files)} rules in {args.all}...\n')
        print('=== YAML Syntax ===')
        errors += check_yaml(files)
        print('\n=== Required Fields ===')
        errors += check_fields(files)
        print('\n=== Duplicate UUIDs ===')
        errors += check_duplicates(args.all)
    else:
        if args.check_yaml:
            files = read_file_list(args.check_yaml)
            errors += check_yaml(files)
        if args.check_fields:
            files = read_file_list(args.check_fields)
            errors += check_fields(files)
        if args.check_duplicates:
            errors += check_duplicates()

    sys.exit(1 if errors else 0)


if __name__ == '__main__':
    main()
