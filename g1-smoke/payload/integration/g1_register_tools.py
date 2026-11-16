"""Create and load real local Cerebrum packages; never execute a read here."""
import os
from pathlib import Path
from g1_common import AUTHOR, TOOLS, sha, write_json


def main():
    from cerebrum.manager.package import ToolPackage
    from cerebrum.interface import AutoTool
    cache = Path(os.environ["XDG_CACHE_HOME"]).resolve()
    template = Path(__file__).with_name("g1_sdk_tool.py").read_text()
    records = []
    for tool in TOOLS:
        source = template.replace('TOOL_NAME = "read_recovery_inventory"', f'TOOL_NAME = "{tool}"').encode()
        path = AutoTool.TOOL_MANAGER._get_cache_path(AUTHOR, tool, "0.0.1")
        if not path.resolve().is_relative_to(cache):
            raise ValueError("sdk_cache_escaped_owned_directory")
        package = ToolPackage(path)
        package.metadata = {"author": AUTHOR, "name": tool, "version": "0.0.1",
                            "license": "Project-owned native typed read adapter",
                            "entry": "tool.py", "module": "Tool"}
        package.files = {"tool.py": source}
        package.save()
        instance = AutoTool.from_preloaded(AUTHOR + "/" + tool)
        if not callable(instance.run):
            raise ValueError("sdk_loaded_entry_not_callable")
        records.append({"tool": AUTHOR + "/" + tool, "source_sha256": sha(source), "cache_path": str(path)})
    write_json(Path(os.environ["G1_LOG_DIR"]) / "g1-sdk-registration.json",
               {"uploaded": False, "run_invoked": False, "sdk_loader": "AutoTool.from_preloaded", "records": records})


if __name__ == "__main__":
    main()
