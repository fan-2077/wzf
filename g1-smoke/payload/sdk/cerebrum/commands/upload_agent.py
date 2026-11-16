from cerebrum.manager.agent import AgentManager

import argparse
import sys
def main():
    parser = argparse.ArgumentParser(description="Upload agents")
    parser.add_argument(
        "--agent_path",
        required=True
    )
    parser.add_argument(
        "--agenthub_url",
        # default="https://app.aios.foundation"
        default="http://localhost:3000"
    )
    args = parser.parse_args()

    manager = AgentManager(args.agenthub_url)

    agent_package = manager.package_agent(args.agent_path)

    manager.upload_agent(agent_package)

if __name__ == "__main__":
    sys.exit(main())
