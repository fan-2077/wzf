from cerebrum.manager.tool import ToolManager

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Upload tools")
    parser.add_argument(
        "--tool_path",
        required=True
    )
    parser.add_argument(
        "--toolhub_url",
        # default="https://app.aios.foundation"
        default="http://localhost:3000"
    )
    args = parser.parse_args()

    manager = ToolManager(args.toolhub_url)

    tool_package = manager.package_tool(args.tool_path)

    manager.upload_tool(tool_package)

if __name__ == "__main__":
    sys.exit(main())
