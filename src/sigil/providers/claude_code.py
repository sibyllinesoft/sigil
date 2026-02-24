"""Claude Code CLI provider -- uses the already-authenticated `claude` command."""

import asyncio
import json
import os

from sigil.providers.base import Provider


class ClaudeCodeProvider(Provider):
    """Provider that shells out to the `claude` CLI.

    Uses the user's existing Claude Code authentication.
    Runs with no tools (--tools "") for zero privileges.
    """

    def __init__(self, model: str = "haiku", max_tokens: int = 1024):
        self._model = model
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return f"claude-code:{self._model}"

    async def complete(self, system_prompt: str, user_message: str) -> str:
        env = os.environ.copy()
        env.pop("CLAUDECODE", None)  # allow nested invocation

        cmd = [
            "claude",
            "-p",
            "--model", self._model,
            "--tools", "",
            "--output-format", "json",
            "--no-session-persistence",
            "--system-prompt", system_prompt,
            user_message,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            err = stderr.decode().strip()
            raise RuntimeError(f"claude CLI failed (exit {proc.returncode}): {err}")

        raw = stdout.decode().strip()
        try:
            data = json.loads(raw)
            # --output-format json returns {"type":"result","result":"..."}
            return data.get("result", raw)
        except json.JSONDecodeError:
            return raw
