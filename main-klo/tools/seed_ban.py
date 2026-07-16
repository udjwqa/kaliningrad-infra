"""Direct auto_ban.emit() helper для pentest codes требующих real PI tokens.

Usage:
    python tools/seed_ban.py emit --ip 192.0.2.1 --pkg com.test --code pi_nonce_replay --ttl 3600
    python tools/seed_ban.py is_banned --ip 192.0.2.1 --pkg com.test
    python tools/seed_ban.py unban --ip 192.0.2.1 --pkg com.test
"""

import sys
import os
import asyncio
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

# Force enforce ON для seed (иначе emit пишет shadow)
os.environ.setdefault("AUTOBAN_ENFORCE", "true")
os.environ.setdefault("AUTOBAN_G2_READY", "true")

from auto_ban import auto_ban
from database import async_session
from db_models import AutoBannedEntry
from sqlalchemy import select, delete


async def cmd_emit(args):
    await auto_ban.connect()
    ok = await auto_ban.emit(
        ip=args.ip,
        package_name=args.pkg,
        code=args.code,
        reason=args.reason or f"pentest seed: {args.code}",
        ttl_sec=args.ttl,
    )
    print(f"emit({args.ip}, {args.pkg}, {args.code}) → enforce={ok}")
    await auto_ban.close()


async def cmd_is_banned(args):
    await auto_ban.connect()
    banned, code = await auto_ban.is_banned(args.ip, args.pkg)
    print(f"is_banned({args.ip}, {args.pkg}) → {banned} code={code!r}")
    await auto_ban.close()


async def cmd_unban(args):
    await auto_ban.connect()
    async with async_session() as session:
        r = await session.execute(
            select(AutoBannedEntry).where(
                AutoBannedEntry.ip == args.ip,
            )
        )
        entries = r.scalars().all()
        if not entries:
            print(f"no DB entries for ip={args.ip}")
        for e in entries:
            ok = await auto_ban.unban(str(e.id))
            print(f"unban {e.id} pkg={e.package_name} → {ok}")
    await auto_ban.close()


async def cmd_clear(args):
    """Cleanup всех pentest IPs (192.0.2.*, 198.51.100.*, 203.0.113.*)."""
    await auto_ban.connect()
    async with async_session() as session:
        r = await session.execute(
            delete(AutoBannedEntry).where(
                AutoBannedEntry.ip.like("192.0.2.%")
                | AutoBannedEntry.ip.like("198.51.100.%")
                | AutoBannedEntry.ip.like("203.0.113.%")
            )
        )
        await session.commit()
        print(f"deleted {r.rowcount} pentest DB entries")
    if auto_ban._redis:
        for prefix in ["192.0.2.", "198.51.100.", "203.0.113."]:
            keys = await auto_ban._redis.keys(f"autoban:*:{prefix}*")
            if keys:
                await auto_ban._redis.delete(*keys)
                print(f"deleted {len(keys)} Redis keys matching {prefix}*")
    await auto_ban.close()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("emit")
    e.add_argument("--ip", required=True)
    e.add_argument("--pkg", default=None)
    e.add_argument("--code", required=True)
    e.add_argument("--ttl", type=int, default=3600)
    e.add_argument("--reason", default=None)
    e.set_defaults(func=cmd_emit)

    b = sub.add_parser("is_banned")
    b.add_argument("--ip", required=True)
    b.add_argument("--pkg", default=None)
    b.set_defaults(func=cmd_is_banned)

    u = sub.add_parser("unban")
    u.add_argument("--ip", required=True)
    u.add_argument("--pkg", default=None)
    u.set_defaults(func=cmd_unban)

    c = sub.add_parser("clear")
    c.set_defaults(func=cmd_clear)

    args = p.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
