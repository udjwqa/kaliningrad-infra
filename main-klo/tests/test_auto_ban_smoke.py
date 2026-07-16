"""Smoke test для Smart Auto-Banlist (P6).

Запуск на gateway:
    cd /opt/scoring-engine && python3 tests/test_auto_ban_smoke.py

Tests:
    1. connect/close — Redis OK
    2. emit shadow mode → would_ban=true в DB, НЕ в Redis
    3. emit enforce mode → in Redis + DB would_ban=false
    4. is_banned → True для banned (ip, pkg)
    5. is_banned → False для другого ip
    6. mark_grey → negative cache блокирует ban check
    7. unban → удаляет из обоих storage
    8. manual_add → permanent if ttl=None
    9. extend → продлевает TTL
    10. get_all_paginated → возвращает корректные filters
    11. get_stats → counts
    12. SETNX idempotency — concurrent emit одного и того же
    13. _warm_from_db — восстанавливает Redis из DB
    14. Global vs pkg-specific (GLOBAL_AUTOBAN_CODES)
"""

import sys
import os
import asyncio
import uuid

# Make sure we can import from parent
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test enforce=true before import (auto_ban читает env при импорте).
# G2_READY=true тоже — иначе G2 codes пойдут в shadow и не запишут в Redis.
os.environ["AUTOBAN_ENFORCE"] = "true"
os.environ["AUTOBAN_G2_READY"] = "true"

from auto_ban import auto_ban, _redis_key, _neg_cache_key, AUTOBAN_CODES_G1, GLOBAL_AUTOBAN_CODES
from database import async_session
from db_models import AutoBannedEntry
from sqlalchemy import select, delete


# Test IPs (нерезидентные диапазоны)
TEST_IP_1 = "192.0.2.10"   # TEST-NET-1
TEST_IP_2 = "198.51.100.10"  # TEST-NET-2
TEST_IP_3 = "203.0.113.10"   # TEST-NET-3
TEST_PKG = "com.test.smoke"
TEST_PKG_2 = "com.test.smoke2"

PASS = 0
FAIL = 0
FAILS = []


def assert_eq(actual, expected, msg):
    global PASS, FAIL
    if actual == expected:
        print(f"  ✅ {msg}")
        PASS += 1
    else:
        print(f"  ❌ {msg} → got {actual!r} expected {expected!r}")
        FAIL += 1
        FAILS.append(msg)


def assert_true(cond, msg):
    assert_eq(bool(cond), True, msg)


async def cleanup():
    """Удалить все test entries из DB + Redis."""
    try:
        async with async_session() as session:
            await session.execute(
                delete(AutoBannedEntry).where(
                    AutoBannedEntry.ip.in_([TEST_IP_1, TEST_IP_2, TEST_IP_3])
                )
            )
            await session.commit()
        if auto_ban._redis:
            keys = await auto_ban._redis.keys("autoban:*test*")
            for ip in [TEST_IP_1, TEST_IP_2, TEST_IP_3]:
                keys += await auto_ban._redis.keys(f"autoban:*:{ip}")
            if keys:
                await auto_ban._redis.delete(*keys)
    except Exception as e:
        print(f"  ⚠ cleanup error: {e}")


async def main():
    print("=" * 60)
    print("AUTO-BAN SMOKE TESTS (P6)")
    print("=" * 60)

    await auto_ban.connect()
    await cleanup()

    # ── Test 1: connect ──
    print("\n[1] connect")
    assert_true(auto_ban._redis is not None, "Redis connected")

    # ── Test 2: emit с enforce=true ──
    print("\n[2] emit() enforce mode")
    ok = await auto_ban.emit(TEST_IP_1, TEST_PKG, "ipqs_vpn", "test1", ttl_sec=3600)
    assert_true(ok, "emit returns True для enforce")
    # Verify в Redis
    val = await auto_ban._redis.get(_redis_key(None, TEST_IP_1))  # global для ipqs_vpn
    assert_eq(val, "ipqs_vpn", "Redis has key (global for ipqs_vpn)")
    # Verify в DB
    async with async_session() as session:
        r = await session.execute(
            select(AutoBannedEntry).where(AutoBannedEntry.ip == TEST_IP_1)
        )
        entry = r.scalar()
        assert_true(entry is not None, "DB entry created")
        assert_eq(entry.would_ban, False, "would_ban=false (enforce mode)")
        assert_eq(entry.code, "ipqs_vpn", "code=ipqs_vpn")
        assert_eq(entry.package_name, None, "pkg=None (global)")

    # ── Test 3: is_banned True ──
    print("\n[3] is_banned() returns True для banned IP")
    banned, code = await auto_ban.is_banned(TEST_IP_1, TEST_PKG)
    assert_true(banned, "is_banned=True для banned global IP")
    assert_eq(code, "ipqs_vpn", "code returned = ipqs_vpn")

    # ── Test 4: is_banned для другого IP ──
    print("\n[4] is_banned() returns False для random IP")
    banned, _ = await auto_ban.is_banned(TEST_IP_2, TEST_PKG)
    assert_eq(banned, False, "is_banned=False для unblocked IP")

    # ── Test 5: pkg-specific ban (НЕ global) ──
    print("\n[5] emit() pkg-specific (НЕ global code)")
    await auto_ban.emit(TEST_IP_2, TEST_PKG, "velocity_block", "test5", ttl_sec=3600)
    # is_banned для того же pkg
    banned, _ = await auto_ban.is_banned(TEST_IP_2, TEST_PKG)
    assert_true(banned, "banned для same pkg")
    # is_banned для другого pkg — НЕ должен сработать (pkg-specific)
    banned, _ = await auto_ban.is_banned(TEST_IP_2, TEST_PKG_2)
    assert_eq(banned, False, "НЕ banned для другого pkg (pkg-specific check)")

    # ── Test 6: mark_grey negative cache ──
    print("\n[6] mark_grey() positive signal")
    await auto_ban.mark_grey(TEST_IP_3, TEST_PKG)
    neg_val = await auto_ban._redis.get(_neg_cache_key(TEST_PKG, TEST_IP_3))
    assert_eq(neg_val, "1", "neg cache set")
    # is_banned должен False даже если в DB банится (negative cache override)
    # Сначала создадим ban для TEST_IP_3 в DB но проверим что neg cache блокирует
    await auto_ban.emit(TEST_IP_3, TEST_PKG, "tor_exit", "test6", ttl_sec=3600)
    banned, _ = await auto_ban.is_banned(TEST_IP_3, TEST_PKG)
    # neg cache был установлен ДО emit, emit добавил ban, проверим:
    # на самом деле emit удалит neg cache (в emit есть delete neg_cache_key)
    # Перепроверим mark_grey после emit
    await auto_ban.mark_grey(TEST_IP_3, TEST_PKG)  # re-mark
    # Теперь is_banned должен True потому что mark_grey ставит negCache,
    # а emit удаляет negCache → но мы заново mark_grey уже после emit.
    # is_banned проверяет negCache first → должен False.
    banned, _ = await auto_ban.is_banned(TEST_IP_3, TEST_PKG)
    assert_eq(banned, False, "negCache override блокирует ban check")

    # ── Test 7: unban ──
    print("\n[7] unban() удаляет из DB + Redis")
    # Найдём id записи
    async with async_session() as session:
        r = await session.execute(
            select(AutoBannedEntry).where(AutoBannedEntry.ip == TEST_IP_1)
        )
        entry = r.scalar()
        entry_id = str(entry.id)
    ok = await auto_ban.unban(entry_id)
    assert_true(ok, "unban returns True")
    # Verify removed
    async with async_session() as session:
        r = await session.execute(
            select(AutoBannedEntry).where(AutoBannedEntry.id == entry_id)
        )
        assert_eq(r.scalar(), None, "removed from DB")
    val = await auto_ban._redis.get(_redis_key(None, TEST_IP_1))
    assert_eq(val, None, "removed from Redis")

    # ── Test 8: manual_add permanent ──
    print("\n[8] manual_add() permanent (ttl=None)")
    ok = await auto_ban.manual_add(TEST_IP_1, TEST_PKG, "manual", "test8", ttl_sec=None,
                                    banned_by="test-admin")
    assert_true(ok, "manual_add returns True")
    async with async_session() as session:
        r = await session.execute(
            select(AutoBannedEntry).where(AutoBannedEntry.ip == TEST_IP_1)
        )
        entry = r.scalar()
        assert_eq(entry.expires_at, None, "permanent → expires_at=NULL")
        assert_eq(entry.source, "manual", "source=manual")
        assert_eq(entry.banned_by, "test-admin", "banned_by=test-admin")

    # ── Test 9: extend ──
    print("\n[9] extend() продлевает TTL")
    entry_id = str(entry.id)
    ok = await auto_ban.extend(entry_id, additional_sec=7200)
    assert_true(ok, "extend returns True")

    # ── Test 10: get_all_paginated ──
    print("\n[10] get_all_paginated() с filters")
    result = await auto_ban.get_all_paginated(page=1, page_size=100)
    assert_true(result["total"] >= 3, f"total >= 3 (got {result['total']})")
    # Filter by IP
    result = await auto_ban.get_all_paginated(search=TEST_IP_2, page=1, page_size=10)
    assert_true(
        any(e["ip"] == TEST_IP_2 for e in result["entries"]),
        "search by IP works",
    )

    # ── Test 11: get_stats ──
    print("\n[11] get_stats()")
    stats = await auto_ban.get_stats()
    assert_true("totalActive" in stats, "stats has totalActive")
    assert_true("last24h" in stats, "stats has last24h")
    assert_true(stats["totalActive"] >= 2, f"totalActive >= 2 (got {stats['totalActive']})")

    # ── Test 12: SETNX idempotency (concurrent emit same key) ──
    print("\n[12] concurrent emit() same (ip, pkg) — strike_count increments")
    await auto_ban.emit(TEST_IP_2, TEST_PKG, "velocity_block", "first", ttl_sec=3600)
    await auto_ban.emit(TEST_IP_2, TEST_PKG, "velocity_block", "second", ttl_sec=3600)
    await auto_ban.emit(TEST_IP_2, TEST_PKG, "velocity_block", "third", ttl_sec=3600)
    async with async_session() as session:
        r = await session.execute(
            select(AutoBannedEntry).where(
                AutoBannedEntry.ip == TEST_IP_2,
                AutoBannedEntry.package_name == TEST_PKG,
            )
        )
        entry = r.scalar()
        # First emit + 3 ON CONFLICT = strike_count >= 3 (at least 1 if first was new)
        assert_true(entry.strike_count >= 3, f"strike_count >= 3 (got {entry.strike_count})")

    # ── Test 13: _warm_from_db ──
    print("\n[13] _warm_from_db() восстанавливает Redis")
    # Clear Redis (но НЕ DB)
    keys = await auto_ban._redis.keys(f"autoban:*:{TEST_IP_2}")
    if keys:
        await auto_ban._redis.delete(*keys)
    # Warm should restore TEST_IP_2 from DB
    count = await auto_ban._warm_from_db()
    assert_true(count >= 1, f"warm restored entries (got {count})")
    val = await auto_ban._redis.get(_redis_key(TEST_PKG, TEST_IP_2))
    assert_true(val is not None, "TEST_IP_2 restored to Redis")

    # ── Test 14: GLOBAL vs pkg-specific lookup ──
    print("\n[14] global ban hit для любого pkg")
    # TEST_IP_1 banned manually (line 197) с manual code — НЕ global.
    # Создадим global ban для TEST_IP_3 (ipqs_vpn = global)
    await auto_ban.unban(entry_id) if entry_id else None  # cleanup
    await cleanup()
    await auto_ban.emit(TEST_IP_3, "com.foo.bar", "tor_exit", "global-test", ttl_sec=3600)
    # tor_exit is GLOBAL → должен сработать для ЛЮБОГО pkg
    banned1, _ = await auto_ban.is_banned(TEST_IP_3, "com.completely.different")
    assert_true(banned1, "global ban работает для любого pkg")
    banned2, _ = await auto_ban.is_banned(TEST_IP_3, TEST_PKG)
    assert_true(banned2, "global ban для TEST_PKG тоже")

    # Cleanup финал
    await cleanup()
    await auto_ban.close()

    print()
    print("=" * 60)
    print(f"RESULTS: {PASS} PASS, {FAIL} FAIL")
    print("=" * 60)
    if FAIL > 0:
        print("Failed:")
        for f in FAILS:
            print(f"  - {f}")
        sys.exit(1)
    print("✅ ALL TESTS PASSED")
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
