from pydantic import BaseModel
from typing import List, Dict, Any, Union, Optional
from cerebrum.utils.communication import Query, send_request, Response
from cerebrum.config.config_manager import config

aios_kernel_url = config.get_kernel_url()

class ToolQuery(Query):
    """
    Query class for tool operations.
    
    This class represents a request to execute one or more tool operations.
    Tools can be anything from simple calculators to complex data processors.
    
    Attributes:
        query_class: Identifier for tool queries, always set to "tool"
        tool_calls: List of tool call specifications, each containing:
            - name: Tool identifier (e.g., "calculator/basic", "text_processor/summarize")
            - parameters: Dictionary of parameters specific to the tool
        
    Examples:
        ```python
        # Calculator tool example
        query = ToolQuery(
            tool_calls=[{
                "name": "calculator/basic",
                "parameters": {
                    "operation": "add",
                    "numbers": [1, 2, 3]
                }
            }]
        )
        
        # Text processing tool example
        query = ToolQuery(
            tool_calls=[{
                "name": "text/summarizer",
                "parameters": {
                    "text": "Long text to summarize...",
                    "max_length": 100
                }
            }]
        )
        ```
    """
    query_class: str = "tool"
    tool_calls: List[Dict[str, Union[str, Any]]]

    class Config:
        arbitrary_types_allowed = True

class ToolResponse(Response):
    """
    Response class for tool operations.
    
    This class represents the result of executing one or more tool operations.
    It includes both successful results and error information if the operation failed.
    
    Attributes:
        response_class: Identifier for tool responses, always set to "tool"
        response_message: Tool execution result, can be string or structured data
        finished: Whether execution completed successfully
        error: Error message if any
        status_code: HTTP status code indicating the result status
        
    Examples:
        ```python
        # Successful calculator response
        response = ToolResponse(
            response_message="6",  # Result of 1 + 2 + 3
            finished=True,
            status_code=200
        )
        
        # Successful text processing response
        response = ToolResponse(
            response_message={
                "summary": "Shortened text...",
                "length": 95,
                "compression_ratio": 0.75
            },
            finished=True,
            status_code=200
        )
        
        # Error response
        response = ToolResponse(
            response_message="Invalid operation requested",
            finished=True,
            error="UnsupportedOperationError",
            status_code=400
        )
        
        # Partial success with multiple tools
        response = ToolResponse(
            response_message=[
                {"status": "success", "data": "..."}, 
                {"status": "error", "message": "Processing failed"}
            ],
            finished=True,
            status_code=207  # Multi-Status
        )
        ```
    """
    response_class: str = "tool"
    response_message: Optional[str] = None
    finished: bool = False
    error: Optional[str] = None
    status_code: int = 200

def call_tool(
        agent_name: str, 
        tool_calls: List[Dict[str, Any]],
        base_url: str = aios_kernel_url
    ) -> ToolResponse:
    """
    Execute one or more tool calls.
    
    This function allows agents to use various tools by specifying the tool name
    and parameters. Multiple tools can be called in sequence, and their results
    can be combined or processed further.
    
    Args:
        agent_name: Name of the agent making the tool call
        tool_calls: List of tool call specifications, each containing:
            - name: Tool identifier
            - parameters: Tool-specific parameters
        base_url: API base URL for the tool service
        
    Returns:
        ToolResponse containing the results or error information
        
    Examples:
        ```python
        # Basic calculator example
        response = call_tool(
            "agent1",
            [{
                "name": "calculator/basic",
                "parameters": {
                    "operation": "multiply",
                    "numbers": [3, 4]
                }
            }]
        )
        if response.finished:
            print(f"Result: {response.response_message}")  # "12"
            
        # Text analysis example
        response = call_tool(
            "agent1",
            [{
                "name": "text/analyzer",
                "parameters": {
                    "text": "Sample text for analysis",
                    "metrics": ["sentiment", "keywords"]
                }
            }]
        )
        if response.finished:
            analysis = response.response_message
            print(f"Sentiment: {analysis['sentiment']}")
            print(f"Keywords: {', '.join(analysis['keywords'])}")
            
        # Multi-tool workflow example
        response = call_tool(
            "agent1",
            [
                {
                    "name": "data/fetch",
                    "parameters": {"source": "database", "query": "SELECT * FROM users"}
                },
                {
                    "name": "data/transform",
                    "parameters": {"format": "csv", "fields": ["id", "name", "email"]}
                },
                {
                    "name": "file/save",
                    "parameters": {"path": "output/users.csv"}
                }
            ]
        )
        if response.finished:
            print("Data processing workflow completed successfully")
        else:
            print(f"Workflow failed: {response.error}")
        ```
        
    Notes:
        - Tools must be registered and available in the system
        - Some tools may require specific permissions
        - Complex workflows may take longer to execute
        - Error handling should account for partial successes in multi-tool calls
    """
    query = ToolQuery(tool_calls=tool_calls)
    return send_request(agent_name, query, base_url)