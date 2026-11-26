from proxy.modules.base import SecurityModule


class ModuleRegistry:
    def __init__(self):
        self._modules: dict[str, SecurityModule] = {}

    def register(self, module: SecurityModule) -> None:
        """
        Given a SecurityModule, register it by its unique ID.
        """

        # No duplicate IDs allowed... bad news bears
        if module.id in self._modules:
            raise ValueError(f"Module '{module.id}' is already registered!")

        # Non duplicate module, all kosher. Send it
        self._modules[module.id] = module

    # Interface for futzing w/ modules via security registry
    # External sources refer via module_id, not SecurityModule itself

    def get(self, module_id: str):
        return self._modules[module_id]

    def get_all(self) -> list[SecurityModule]:
        return list(self._modules.values())
