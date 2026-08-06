"""Run both Miau backend services: TCP+TLS listener and FastAPI REST panel.

Usage:
    python run.py [--port TCP_PORT] [--api-port API_PORT] [--no-rest]
"""
from __future__ import annotations

import argparse
import asyncio
import logging

import uvicorn

from config import load as load_cfg
from listener import Listener
from store import Store


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.toml")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--api-port", type=int, default=None)
    ap.add_argument("--no-rest", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    cfg = load_cfg(args.config)
    if args.port:
        cfg.server.tcp_port = args.port
    if args.api_port:
        cfg.server.api_port = args.api_port

    store = Store(cfg.store.db_path)
    listener = Listener(cfg, store)

    async def _amain() -> None:
        if args.no_rest:
            await listener.run()
        else:
            import api as panel_api
            panel_api._cfg = cfg
            panel_api._store = store
            config = uvicorn.Config(
                panel_api.app,
                host=cfg.server.host,
                port=cfg.server.api_port,
                log_level="info",
            )
            server = uvicorn.Server(config)
            await asyncio.gather(
                listener.run(),
                server.serve(),
            )

    asyncio.run(_amain())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
