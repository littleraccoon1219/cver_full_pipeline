#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))  #让脚本能 import 到项目里的其他模块

from cver.knowledge.formal_schema import schema_report, seed_actor, seed_root_cause_taxonomy
from cver.knowledge.schema import init_trusted_kb


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def main() -> int:
    parser = argparse.ArgumentParser(description='Upgrade/create the PhD formal trusted-KB schema.')
    parser.add_argument('--db', default='data/trusted_knowledge.db')
    parser.add_argument('--actor-id', default='researcher-yupeng')
    parser.add_argument('--actor-name', default='Yupeng')
    parser.add_argument('--taxonomy', default='taxonomy/root_causes.yaml')
    parser.add_argument('--no-backup', action='store_true')
    parser.add_argument('--no-seed-taxonomy', action='store_true')
    args = parser.parse_args()

    db_path = Path(args.db)
    backup = None
    if db_path.exists() and not args.no_backup:
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        backup = db_path.with_name(f'{db_path.name}.before-formal-{stamp}.bak')
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(db_path, backup)

    init_trusted_kb(db_path, now_iso())
    seed_actor(db_path, args.actor_id, args.actor_name)
    taxonomy_result = None
    if not args.no_seed_taxonomy:
        taxonomy_result = seed_root_cause_taxonomy(db_path, args.taxonomy, args.actor_id)
    report = schema_report(db_path)
    print(json.dumps({
        'ok': not report['missing_tables'] and not report['foreign_key_errors'],
        'db': str(db_path),
        'backup': str(backup) if backup else None,
        'taxonomy': taxonomy_result,
        'report': report,
    }, ensure_ascii=False, indent=2))
    return 0 if not report['missing_tables'] and not report['foreign_key_errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
