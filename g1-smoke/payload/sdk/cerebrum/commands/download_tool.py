from cerebrum.manager.tool import ToolManager

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Download tools")
    parser.add_argument(
        "--tool_author",
        required=True
    )
    parser.add_argument(
        "--tool_name",
        required=True
    )
    parser.add_argument(
        "--tool_version",
        required=False
    )
    parser.add_argument(
        "--toolhub_url",
        # default="https://app.aios.foundation"
        default="http://localhost:3000"
    )
    args = parser.parse_args()

    manager = ToolManager(args.toolhub_url)

    tool = manager.download_tool(args.tool_author, args.tool_name, args.tool_version)
    print(tool)

if __name__ == "__main__":
    sys.exit(main())
