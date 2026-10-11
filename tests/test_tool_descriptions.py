"""Tool descriptions stay short enough for MCP clients, and key schemas keep their arguments."""
import pytest

from diskhoard import agent as agentmod

MAX_DESCRIPTION_CHARS = 750

EXPECTED_PROPS = {
    "disk_zip_split": {
        "path", "out_dir", "limit", "margin", "prefix", "sort", "compression", "too_large",
        "include", "exclude", "overwrite", "manifest", "confirm", "wait", "timeout_s",
    },
    "disk_ollama_backups": {"models_dir", "kind", "safe_only", "limit"},
    "disk_ollama_free": {"ids", "models_dir", "dry_run", "confirm", "mode"},
}


def _by_name():
    return {t["name"]: t for t in agentmod.CATALOG}


@pytest.mark.parametrize("name", agentmod.TOOL_NAMES)
def test_description_is_short(name):
    desc = _by_name()[name]["description"]
    assert len(desc) <= MAX_DESCRIPTION_CHARS, "%s description has %d chars" % (name, len(desc))


@pytest.mark.parametrize("name", sorted(EXPECTED_PROPS))
def test_schema_properties_unchanged(name):
    schema = _by_name()[name]["inputSchema"]
    assert set(schema["properties"]) == EXPECTED_PROPS[name]
