"""
Docs Hub — /api/gh-doc (2026-07-09).

Server-side чтение SDK репо из локального зеркала на КЛО.
Репо `redzov/android-sdk-v3` приватный — вместо fetch к raw.githubusercontent
(который отдаёт 404 без auth) мы держим локальный клон + cron sync каждые 15 мин.
Панель бьёт /api/gh-doc — сервер отдаёт содержимое файла с диска.

Path traversal защита: разрешены только относительные пути без `..`.
Ref switching: `git worktree` бы усложнил, поэтому просто читаем из main;
для tag view — предмет второй итерации.
"""
import os
import subprocess
from pathlib import Path

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse

router = APIRouter()

REPO_ROOT = Path(os.getenv("GH_MIRROR_ROOT", "/opt/panel-repos/android-sdk-v3"))
MAX_FILE_SIZE = 500_000  # 500 KB safety cap


def _safe_resolve(rel_path: str) -> Path | None:
    """Резолвит путь и проверяет что он внутри REPO_ROOT (защита от traversal)."""
    if not rel_path or rel_path.startswith("/"):
        return None
    if ".." in rel_path.split("/"):
        return None
    full = (REPO_ROOT / rel_path).resolve()
    try:
        full.relative_to(REPO_ROOT.resolve())
    except ValueError:
        return None
    return full


@router.get("/api/gh-doc/status")
async def gh_doc_status():
    """Отдаёт текущее состояние зеркала — HEAD SHA, tag, время последнего sync."""
    if not REPO_ROOT.exists():
        return {"ok": False, "error": "mirror not initialized", "path": str(REPO_ROOT)}
    try:
        head_sha = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            stderr=subprocess.STDOUT, timeout=5,
        ).decode().strip()
        branch = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.STDOUT, timeout=5,
        ).decode().strip()
        # Возьмём последний tag на HEAD (если есть)
        try:
            last_tag = subprocess.check_output(
                ["git", "-C", str(REPO_ROOT), "describe", "--tags", "--abbrev=0"],
                stderr=subprocess.DEVNULL, timeout=5,
            ).decode().strip()
        except subprocess.CalledProcessError:
            last_tag = None
        # Список тегов
        tags_raw = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "tag", "-l", "--sort=-v:refname"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode().strip()
        tags = [t for t in tags_raw.split("\n") if t][:20]
        # mtime .git/FETCH_HEAD — приблизительное время последнего fetch
        fetch_head = REPO_ROOT / ".git" / "FETCH_HEAD"
        last_sync = None
        if fetch_head.exists():
            last_sync = int(fetch_head.stat().st_mtime)
        return {
            "ok": True,
            "head_sha": head_sha,
            "branch": branch,
            "last_tag": last_tag,
            "tags": tags,
            "last_sync_ts": last_sync,
        }
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}


@router.get("/api/gh-doc/tree")
async def gh_doc_tree(ref: str = Query(default="HEAD")):
    """Дерево файлов (только blob) по указанной ref (branch/tag/SHA)."""
    if not REPO_ROOT.exists():
        return JSONResponse({"error": "mirror not initialized"}, status_code=503)
    try:
        raw = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "ls-tree", "-lr", ref],
            stderr=subprocess.PIPE, timeout=10,
        ).decode()
    except subprocess.CalledProcessError as e:
        return JSONResponse(
            {"error": f"git ls-tree failed: {e.stderr.decode()[:200]}"},
            status_code=400,
        )
    items = []
    for line in raw.splitlines():
        # format: <mode> <type> <sha>\t<size>\t<path>
        # ls-tree -lr: 100644 blob <sha> <size>\t<path>
        try:
            meta, path = line.split("\t", 1)
        except ValueError:
            continue
        parts = meta.split()
        if len(parts) < 4 or parts[1] != "blob":
            continue
        size_str = parts[3]
        try:
            size = int(size_str)
        except ValueError:
            size = None
        # Skip dotfiles/dotfolders
        if path.startswith(".") or "/." in path:
            continue
        items.append({"path": path, "size": size, "sha": parts[2]})
    return {"ok": True, "ref": ref, "count": len(items), "tree": items}


@router.get("/api/gh-doc/blob")
async def gh_doc_blob(
    path: str = Query(..., min_length=1, max_length=500),
    ref: str = Query(default="HEAD"),
):
    """Содержимое одного файла в указанной ref."""
    if not REPO_ROOT.exists():
        return JSONResponse({"error": "mirror not initialized"}, status_code=503)
    # Traversal защита — только валидные относительные пути
    if not path or path.startswith("/") or ".." in path.split("/"):
        return JSONResponse({"error": "invalid path"}, status_code=400)
    try:
        # Проверим размер
        try:
            size_raw = subprocess.check_output(
                ["git", "-C", str(REPO_ROOT), "cat-file", "-s", f"{ref}:{path}"],
                stderr=subprocess.PIPE, timeout=5,
            ).decode().strip()
            size = int(size_raw)
            if size > MAX_FILE_SIZE:
                return JSONResponse(
                    {"error": f"file too large ({size} bytes, max {MAX_FILE_SIZE})"},
                    status_code=413,
                )
        except subprocess.CalledProcessError:
            return JSONResponse({"error": "file not found in ref"}, status_code=404)
        raw = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "cat-file", "-p", f"{ref}:{path}"],
            stderr=subprocess.PIPE, timeout=8,
        )
    except subprocess.CalledProcessError as e:
        return JSONResponse(
            {"error": f"git cat-file failed: {e.stderr.decode()[:200]}"},
            status_code=400,
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return JSONResponse({"error": "binary file"}, status_code=415)
    return PlainTextResponse(text, media_type="text/plain; charset=utf-8")
