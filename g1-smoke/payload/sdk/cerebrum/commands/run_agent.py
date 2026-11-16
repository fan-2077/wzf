#!/usr/bin/env python
from cerebrum.manager.agent import AgentManager
from cerebrum.utils.manager import get_newest_version
import argparse
import os
import sys
import json
import logging
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class AgentConfig:
    """
    Data class to hold agent configuration parameters.
    
    Attributes:
        agent_path (str): Local path to the agent directory
        agent_author (str): Author of the remote agent
        agent_name (str): Name of the remote agent
        agent_version (str): Version of the agent
        agenthub_url (str): Base URL for the Cerebrum API
        task_input (str): Task input for the agent
        debug (bool): Enable debug logging
        config_path (str): Path to JSON config file
        mode (str): Loading mode ('local' or 'remote')
        share_memory (bool): When True, agent memories use sharing_policy='shared'
    """
    agent_path: Optional[str] = None
    agent_author: Optional[str] = None
    agent_name: Optional[str] = None
    agent_version: Optional[str] = None
    agenthub_url: str = "https://app.aios.foundation"
    task_input: str = ""
    debug: bool = False
    config_path: Optional[str] = None
    mode: Optional[str] = None
    share_memory: bool = False

class AgentRunner:
    """
    Main class responsible for running agents either locally or remotely.
    
    This class handles the initialization, loading, and execution of agents
    while providing proper error handling and logging.
    """
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the AgentRunner with configuration.
        
        Args:
            config (AgentConfig): Configuration parameters for the agent
        """
        self.config = config
        self.manager = AgentManager(config.agenthub_url)
        self._setup_logging()
        
    def _setup_logging(self) -> None:
        """Configure logging based on debug flag."""
        if self.config.debug:
            logger.setLevel(logging.DEBUG)
            logging.getLogger('cerebrum').setLevel(logging.DEBUG)
    
    def _load_json_config(self) -> Dict[str, Any]:
        """
        Load configuration from JSON file if provided.
        
        Returns:
            Dict[str, Any]: Configuration dictionary
        """
        if not self.config.config_path:
            return {}
            
        try:
            with open(self.config.config_path, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {self.config.config_path}")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def _load_local_agent(self) -> Tuple[Any, Dict[str, Any]]:
        """
        Load agent from local path.
        
        Returns:
            Tuple[Any, Dict[str, Any]]: Tuple of (agent_class, agent_config)
        """
        if not os.path.exists(self.config.agent_path):
            logger.error(f"Provided agent path does not exist: {self.config.agent_path}")
            sys.exit(1)
            
        agent_class, agent_config = self.manager.load_agent(local=True, path=self.config.agent_path)
        logger.info(f"Loaded local agent: {agent_config.get('name', 'unknown')}")
        return agent_class, agent_config
    
    def _load_remote_agent(self) -> Tuple[Any, Dict[str, Any]]:
        """
        Load agent from remote source with version checking.
        
        Returns:
            Tuple[Any, Dict[str, Any]]: Tuple of (agent_class, agent_config)
        """
        try:
            # Check cache first
            cached_versions = self.manager._get_cached_versions(self.config.agent_author, self.config.agent_name)
            if self.config.agent_version in cached_versions:
                logger.info(f"Using cached version: {self.config.agent_version}")
                version_to_use = self.config.agent_version
            else:
                # Try downloading specified version
                try:
                    logger.info(f"Version {self.config.agent_version} not found in cache, attempting to download...")
                    author, name, version = self.manager.download_agent(
                        self.config.agent_author, 
                        self.config.agent_name, 
                        self.config.agent_version
                    )
                    version_to_use = version
                    logger.info(f"Downloaded agent version: {version_to_use}")
                except Exception as e:
                    logger.error(
                        f"Version {self.config.agent_version} does not exist for agent "
                        f"{self.config.agent_author}/{self.config.agent_name}"
                    )
                    sys.exit(1)
                    
            agent_class, agent_config = self.manager.load_agent(
                author=self.config.agent_author,
                name=self.config.agent_name,
                version=version_to_use
            )
            logger.info(f"Loaded remote agent: {self.config.agent_author}/{self.config.agent_name} (v{version_to_use})")
            return agent_class, agent_config
            
        except Exception as e:
            logger.error(f"Failed to check or download agent: {e}")
            sys.exit(1)
    
    def run(self) -> Any:
        """
        Main method to run the agent with proper configuration.
        
        Returns:
            Any: Result from the agent execution
        """
        try:
            # Load JSON config if provided
            config = self._load_json_config()
            
            # Load agent based on mode
            if self.config.mode == "local":
                agent_class, agent_config = self._load_local_agent()
            else:  # remote mode
                agent_class, agent_config = self._load_remote_agent()
            
            # Merge configurations
            merged_config = {**agent_config, **config}
            
            # Initialize and run agent
            agent_name = merged_config.get('name', 'unknown')
            logger.info(f"Initializing agent: {agent_name}")
            agent = agent_class(agent_name)
            
            # Propagate share-memory flag to agent instance.
            # Agents can read this via getattr(self, 'share_memory', False)
            # to determine whether to use sharing_policy="shared" or "private".
            try:
                agent.share_memory = self.config.share_memory
            except AttributeError:
                logger.warning(
                    "Could not set share_memory on agent %s (may use __slots__)",
                    agent_name,
                )
            
            logger.info(f"Running agent: {agent_name}")
            result = agent.run(self.config.task_input)
            
            logger.info("Agent execution completed")
            logger.info(f"Result: {result}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error running agent: {e}", exc_info=True)
            sys.exit(1)

def parse_arguments() -> AgentConfig:
    """
    Parse command line arguments and return AgentConfig.
    
    Returns:
        AgentConfig: Parsed configuration
    """
    parser = argparse.ArgumentParser(description="Run agent")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--agent_path", help="Local path to the agent directory")
    group.add_argument("--agent_author", help="Author of the remote agent")
    
    parser.add_argument("--agent_name", help="Name of the remote agent (required if --agent_author is provided)")
    parser.add_argument("--agent_version", help="Version of the agent to run (required for remote mode)")
    parser.add_argument("--agenthub_url", default="https://app.aios.foundation",
                       help="Base URL for the Cerebrum API (default: https://app.aios.foundation)")
    parser.add_argument("--task_input", help="Task input for the agent", default="")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", help="Path to a JSON config file for the agent")
    parser.add_argument("--mode", choices=["local", "remote"],
                       help="Explicitly specify loading mode: 'local' for local files, 'remote' for remote download")
    parser.add_argument("--share-memory", action="store_true",
                       help="Create memories with sharing_policy='shared' instead of 'private'")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.agent_author and not args.agent_name:
        parser.error("--agent_name is required when --agent_author is provided")
    
    if args.agent_path and args.mode == "remote":
        parser.error("Cannot use --mode=remote with --agent_path (use --agent_author and --agent_name instead)")
    
    if args.agent_author and args.mode == "local":
        parser.error("Cannot use --mode=local with --agent_author (use --agent_path instead)")
    
    # Determine loading mode
    mode = args.mode
    if not mode:
        mode = "local" if args.agent_path else "remote"
    
    # Check required parameters for remote mode
    if mode == "remote" and not args.agent_version:
        parser.error("--agent_version is required for remote mode")
    
    return AgentConfig(
        agent_path=args.agent_path,
        agent_author=args.agent_author,
        agent_name=args.agent_name,
        agent_version=args.agent_version,
        agenthub_url=args.agenthub_url,
        task_input=args.task_input,
        debug=args.debug,
        config_path=args.config,
        mode=mode,
        share_memory=args.share_memory
    )

def main():
    """Main entry point for the script."""
    config = parse_arguments()
    runner = AgentRunner(config)
    runner.run()

if __name__ == "__main__":
    sys.exit(main())
