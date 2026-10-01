"""Custom exceptions for LordShen AI."""

class LordShenError(Exception):
    """Base exception for all LordShen errors."""
    def __init__(self, message: str = "An unspecified LordShen error occurred."):
        self.message = message
        super().__init__(self.message)

class ScopeError(LordShenError):
    """Exception raised for scope validation failures."""
    def __init__(self, message: str = "Scope validation failed."):
        super().__init__(message)

class ToolError(LordShenError):
    """Exception raised for tool execution failures."""
    def __init__(self, message: str = "Tool execution failed.", tool_name: str = "unknown"):
        self.tool_name = tool_name
        super().__init__(f"[{tool_name}] {message}")

class ToolNotFoundError(ToolError):
    """Exception raised when a required tool is not installed."""
    def __init__(self, message: str = "Tool not found or not executable.", tool_name: str = "unknown"):
        super().__init__(message, tool_name)

class LLMError(LordShenError):
    """Exception raised for AI/LLM failures."""
    def __init__(self, message: str = "LLM interaction failed."):
        super().__init__(message)

class ConfigError(LordShenError):
    """Exception raised for configuration issues."""
    def __init__(self, message: str = "Configuration error."):
        super().__init__(message)

class RateLimitError(LLMError):
    """Exception raised for API rate limiting."""
    def __init__(self, message: str = "API rate limit exceeded."):
        super().__init__(message)

class ScanError(LordShenError):
    """Exception raised for scan pipeline errors."""
    def __init__(self, message: str = "Scan pipeline encountered an error."):
        super().__init__(message)
