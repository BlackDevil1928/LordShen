"""Central subprocess execution wrapper for all security tools.

All tool execution MUST go through run_tool() — no raw subprocess usage.
Provides timeout handling, output capture, and consistent error reporting.
"""

import asyncio
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lordshen.core.console import console, print_error, print_info
from lordshen.core.exceptions import ToolError, ToolNotFoundError


@dataclass
class ToolResult:
    """Result from a tool execution."""

    stdout: str
    stderr: str
    return_code: int
    duration: float
    command: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """Check if tool executed successfully."""
        return self.return_code == 0 and not self.timed_out


async def run_tool(
    command: str | list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    stdin_data: str | None = None,
    shell: bool = False,
) -> ToolResult:
    """Execute a security tool as an async subprocess.

    Args:
        command: Command string or list of arguments.
        timeout: Maximum execution time in seconds.
        cwd: Working directory for the command.
        env: Additional environment variables.
        stdin_data: Data to pipe to stdin.
        shell: Whether to use shell execution (avoid when possible).

    Returns:
        ToolResult with stdout, stderr, return code, and timing.

    Raises:
        ToolError: If the tool fails to execute.
    """
    import os

    start_time = time.monotonic()
    cmd_str = command if isinstance(command, str) else " ".join(command)

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    # Add Go binaries to PATH
    go_bin = Path.home() / "go" / "bin"
    if go_bin.exists():
        merged_env["PATH"] = f"{go_bin}:{merged_env.get('PATH', '')}"

    try:
        if isinstance(command, str) or shell:
            process = await asyncio.create_subprocess_shell(
                cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                cwd=cwd,
                env=merged_env,
            )
        else:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                cwd=cwd,
                env=merged_env,
            )

        stdin_bytes = stdin_data.encode() if stdin_data else None
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(input=stdin_bytes), timeout=timeout
        )

        duration = time.monotonic() - start_time
        return ToolResult(
            stdout=stdout_bytes.decode(errors="replace"),
            stderr=stderr_bytes.decode(errors="replace"),
            return_code=process.returncode or 0,
            duration=duration,
            command=cmd_str,
            timed_out=False,
        )

    except asyncio.TimeoutError:
        duration = time.monotonic() - start_time
        try:
            process.kill()
            await process.wait()
        except Exception:
            pass
        return ToolResult(
            stdout="",
            stderr=f"Command timed out after {timeout}s",
            return_code=-1,
            duration=duration,
            command=cmd_str,
            timed_out=True,
        )
    except FileNotFoundError:
        binary = command[0] if isinstance(command, list) else command.split()[0]
        raise ToolNotFoundError(
            f"Tool binary not found: {binary}. "
            f"Run 'lordshen tools --check' to verify installation.",
            tool_name=binary,
        )
    except PermissionError:
        raise ToolError(
            f"Permission denied executing: {cmd_str}. Try with sudo.",
            tool_name=cmd_str.split()[0],
        )
    except Exception as e:
        duration = time.monotonic() - start_time
        raise ToolError(
            f"Failed to execute command: {e}",
            tool_name=cmd_str.split()[0] if cmd_str else "unknown",
        )


def check_binary(name: str) -> bool:
    """Check if a binary is available in PATH."""
    return shutil.which(name) is not None


def get_binary_path(name: str) -> str | None:
    """Get full path to a binary."""
    # Check standard PATH
    path = shutil.which(name)
    if path:
        return path

    # Check Go bin directory
    go_path = Path.home() / "go" / "bin" / name
    if go_path.exists():
        return str(go_path)

    return None


def get_temp_output_path(tool_name: str, extension: str = "json") -> Path:
    """Generate a unique temporary output file path for a tool.

    Args:
        tool_name: Name of the tool (used in filename).
        extension: File extension (default: json).

    Returns:
        Path to a unique temporary file.
    """
    unique_id = uuid.uuid4().hex[:8]
    filename = f"lordshen_{tool_name}_{unique_id}.{extension}"
    return Path(tempfile.gettempdir()) / filename


async def run_tool_with_file_output(
    command: str | list[str],
    output_path: Path,
    timeout: int = 300,
    **kwargs: Any,
) -> tuple[ToolResult, str]:
    """Run a tool and read its output file.

    Args:
        command: Command to execute.
        output_path: Path where tool writes output.
        timeout: Execution timeout.
        **kwargs: Additional arguments for run_tool.

    Returns:
        Tuple of (ToolResult, file_contents).
    """
    result = await run_tool(command, timeout=timeout, **kwargs)

    file_contents = ""
    if output_path.exists():
        try:
            file_contents = output_path.read_text(errors="replace")
        except Exception as e:
            print_error(f"Failed to read output file {output_path}: {e}")
        finally:
            try:
                output_path.unlink()
            except Exception:
                pass

    return result, file_contents
