from cerebrum.manager.agent import AgentManager

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Download agents")
    parser.add_argument(
        "--agent_author",
        required=True
    )
    parser.add_argument(
        "--agent_name",
        required=True
    )
    parser.add_argument(
        "--agent_version",
        required=False
    )
    parser.add_argument(
        "--agenthub_url",
        # default="https://app.aios.foundation"
        default="http://localhost:3000"
    )
    args = parser.parse_args()

    manager = AgentManager(args.agenthub_url)

    agent = manager.download_agent(args.agent_author, args.agent_name, args.agent_version)
    print(agent)

if __name__ == "__main__":
    sys.exit(main())
