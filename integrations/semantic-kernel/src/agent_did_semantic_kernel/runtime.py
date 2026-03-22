"""Optional semantic-kernel runtime helpers for the Agent-DID Semantic Kernel package."""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Callable
from functools import wraps
from typing import Any, cast, get_type_hints

from .tools import SemanticKernelTool


def _load_semantic_kernel_runtime() -> tuple[Any, Any, Any]:
    try:
        functions_module = importlib.import_module("semantic_kernel.functions")
        decorator_module = importlib.import_module("semantic_kernel.functions.kernel_function_decorator")
        method_module = importlib.import_module("semantic_kernel.functions.kernel_function_from_method")
    except ImportError as error:  # pragma: no cover - exercised through runtime smoke when extra is installed
        raise RuntimeError(
            "semantic-kernel runtime helpers require installing agent-did-semantic-kernel[runtime]"
        ) from error

    return (
        getattr(functions_module, "KernelPlugin"),
        getattr(decorator_module, "kernel_function"),
        getattr(method_module, "KernelFunctionFromMethod"),
    )


def _decorate_tool_handler(
    tool: SemanticKernelTool,
    kernel_function: Callable[..., Any],
) -> Callable[..., Any]:
    handler = tool.coroutine or tool.func
    if handler is None:
        raise RuntimeError(f"Tool {tool.name} does not expose a callable handler")

    if inspect.iscoroutinefunction(handler):

        @wraps(handler)
        async def runtime_handler(**kwargs: Any) -> Any:
            return await handler(**kwargs)

    else:

        @wraps(handler)
        def runtime_handler(**kwargs: Any) -> Any:
            return handler(**kwargs)

    signature = inspect.signature(handler)
    resolved_type_hints = get_type_hints(handler)
    runtime_handler.__signature__ = signature.replace(  # type: ignore[attr-defined]
        parameters=[
            parameter.replace(annotation=resolved_type_hints.get(parameter.name, parameter.annotation))
            for parameter in signature.parameters.values()
        ],
        return_annotation=resolved_type_hints.get("return", signature.return_annotation),
    )
    decorated_handler = kernel_function(name=tool.name, description=tool.description)(runtime_handler)
    return cast(Callable[..., Any], decorated_handler)


def create_semantic_kernel_plugin(
    tools: list[SemanticKernelTool],
    *,
    plugin_name: str = "agent_did",
    description: str | None = None,
) -> Any:
    normalized_plugin_name = plugin_name.strip()
    if not normalized_plugin_name:
        raise ValueError("plugin_name must not be empty")

    kernel_plugin_cls, kernel_function, kernel_function_from_method_cls = _load_semantic_kernel_runtime()
    functions = [
        kernel_function_from_method_cls(
            method=_decorate_tool_handler(tool, kernel_function),
            plugin_name=normalized_plugin_name,
        )
        for tool in tools
    ]
    return kernel_plugin_cls(
        name=normalized_plugin_name,
        description=description,
        functions=functions,
    )

