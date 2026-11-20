import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Config:
    raw: dict

    def get(self, section: str, key: str, default=None):
        return self.raw.get(section, {}).get(key, default)


def load(path: str | os.PathLike | None = None) -> Config:
    path = Path(path or os.environ.get("AIFILTER_CONFIG", ROOT / "config.toml"))
    if not path.exists() and (ROOT / ".public-export").exists():  # a fresh public copy before setup only
        path = ROOT / "config.example.toml"
    with open(path, "rb") as f:
        return Config(tomllib.load(f))


def db_path() -> Path:
    return Path(os.environ.get("AIFILTER_DB", ROOT / "data" / "filter.db"))
