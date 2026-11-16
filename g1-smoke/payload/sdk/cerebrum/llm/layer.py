from dataclasses import dataclass

@dataclass
class LLMLayer:
    """
    Data class representing the configuration of an LLM processing layer.
    
    Attributes:
        llm_name (str): Name of the language model to be used.
        max_gpu_memory (Optional[dict]): Dictionary specifying GPU memory allocation settings.
        eval_device (str): The device used for model evaluation (default: "cuda:0").
        max_new_tokens (int): Maximum number of new tokens the model can generate in a response (default: 2048).
        log_mode (str): Logging mode, indicating where logs should be recorded (default: "console").
        llm_backend (str): Backend framework for the LLM (default: "default").
    
    Example:
        ```python
        layer_config = LLMLayer(
            llm_name="qwen2.5-7b",
            max_gpu_memory={"A100": "40GB"},
            eval_device="cuda:0",
            max_new_tokens=2048,
            log_mode="console",
            llm_backend="ollama"
        )
        ```
    """
    llm_name: str
    max_gpu_memory: dict | None = None
    eval_device: str = "cuda:0"
    max_new_tokens: int = 2048
    log_mode: str = "console"
    llm_backend: str = "default"