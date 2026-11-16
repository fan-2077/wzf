import argparse
import datetime
import json
import logging
import os
import sys

from tqdm import tqdm

from cerebrum.utils.communication import get_mcp_server_path, aios_kernel_url

logger = logging.getLogger("desktopenv.experiment")

mcp_server_path = get_mcp_server_path(aios_kernel_url)
# mcp_server_path = os.path.join(os.getcwd(), "aios/tool/mcp_server.py")

# mcp_server_path = os.path.join("/Users/km1558/Documents/projects/dongyuanjushi/OpenAGI2.0", "aios/tool/mcp_server.py")

from cerebrum.example.agents import run_cu_agent

import asyncio

if __name__ == "__main__":
    import sys
    import uuid
    task_input = sys.argv[1]
    task_config = {
        "instruction": task_input,
        "domain": "chrome", 
        "id": str(uuid.uuid4())
    }
    asyncio.run(run_cu_agent(task_config, mcp_server_path))