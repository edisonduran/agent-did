from __future__ import annotations


def pytest_configure(config: object) -> None:
    plugin_manager = getattr(config, "pluginmanager")
    if plugin_manager.hasplugin("asyncio"):
        return

    from pytest_asyncio import plugin as pytest_asyncio_plugin

    plugin_manager.register(pytest_asyncio_plugin, "asyncio")
