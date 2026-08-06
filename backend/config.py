"""Configuration loader for Miau backend."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ServerCfg:
    host: str = "0.0.0.0"
    tcp_port: int = 9000
    api_port: int = 8443
    hb_interval: int = 15
    hb_timeout: int = 60


@dataclass
class TLSCfg:
    cert_dir: str = "./certs"
    common_name: str = "miau-relay"
    org: str = "Miau"
    country: str = "NL"
    valid_days: int = 3650
    rsa_bits: int = 4096


@dataclass
class AuthCfg:
    psk_rotate_hours: int = 168
    totp_issuer: str = "MiauPanel"
    totp_digits: int = 6
    totp_interval: int = 30
    operator_password: str = "miau"


@dataclass
class StoreCfg:
    db_path: str = "./miau.db"


@dataclass
class ModulesCfg:
    dir: str = "./modules"


@dataclass
class Config:
    server: ServerCfg = field(default_factory=ServerCfg)
    tls: TLSCfg = field(default_factory=TLSCfg)
    auth: AuthCfg = field(default_factory=AuthCfg)
    store: StoreCfg = field(default_factory=StoreCfg)
    modules: ModulesCfg = field(default_factory=ModulesCfg)


def load(path: str | Path) -> Config:
    raw: dict[str, Any] = {}
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    cfg = Config()
    for key, dataclass in (
        ("server", ServerCfg),
        ("tls", TLSCfg),
        ("auth", AuthCfg),
        ("store", StoreCfg),
        ("modules", ModulesCfg),
    ):
        if key in raw:
            setattr(cfg, key, dataclass(**{
                k: v
                for k, v in raw[key].items()
                if k in dataclass.__dataclass_fields__
            }))
    return cfg


_DEFAULT: Config | None = None


def default() -> Config:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = load("config.toml")
    return _DEFAULT
