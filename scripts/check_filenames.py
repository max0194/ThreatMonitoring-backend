#!/usr/bin/env python3
import sys
import re
from pathlib import Path

PATTERN = re.compile(r'^[a-z0-9_\-./]+$')

def check_paths(paths):
    bad = []
    for p in paths:
        p = Path(p)
        for part in p.parts:
            if part in ('.', '..'):
                continue
            if not PATTERN.match(part):
                bad.append(str(p))
                break
    return bad

def main():
    args = sys.argv[1:]
    if not args:
        args = [str(p) for p in Path('.').rglob('*') if p.is_file()]
    bad = check_paths(args)
    if bad:
        print('Find files/dirs with invalid names:')
        for b in bad:
            print('  -', b)
        print('\nNames should be in lowercase and can contain digits, hyphens and underscores.')
        sys.exit(1)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
