from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    NEO4J_URI: str = ""
    # Aura's credentials file calls it NEO4J_USERNAME; accept both spellings
    NEO4J_USER: str = Field("neo4j", validation_alias=AliasChoices("NEO4J_USER", "NEO4J_USERNAME"))
    NEO4J_PASSWORD: str = ""

    AIAND_API_KEY: str = ""
    AIAND_BASE_URL: str = "https://api.aiand.example/v1"

    ATTACKER_MODEL: str = "deepseek-chat"
    DEFENDER_MODEL: str = "kimi-k2"
    REPORT_MODEL: str = "kimi-k2"
    REPORT_TIMEOUT: float = 180.0  # seconds per model for the streamed after-action report

    # optional shared secret for every state-changing endpoint (empty = open, for local use).
    # Spectating (the page, /ws, GET endpoints) never needs it.
    WARGAME_TOKEN: str = ""

    # Extra providers for cross-provider benchmarking, as JSON:
    #   {"openai": {"base_url": "https://api.openai.com/v1", "api_key": "sk-..."}, ...}
    # A model id "openai:gpt-4o" then routes to that provider; a bare id uses ai& (AIAND_*).
    MODEL_PROVIDERS: str = "{}"

    GAME_SEED: int = 42
    MAX_TURNS: int = 20
    PATH_METRIC_IMPL: str = "python"  # "python" (fast, default) | "cypher" (showcase)

    @property
    def neo4j_enabled(self) -> bool:
        return bool(self.NEO4J_URI and self.NEO4J_PASSWORD)

    @property
    def aiand_enabled(self) -> bool:
        return bool(self.AIAND_API_KEY) or self.providers != {}

    @property
    def providers(self) -> dict:
        import json
        try:
            p = json.loads(self.MODEL_PROVIDERS)
            return p if isinstance(p, dict) else {}
        except (ValueError, TypeError):
            return {}

    def resolve_model(self, model: str) -> tuple[str, str, str]:
        """model -> (base_url, api_key, bare_model_name). 'prefix:name' routes to a configured
        provider; a bare name uses the ai& gateway (AIAND_*)."""
        if ":" in model:
            prefix, name = model.split(":", 1)
            p = self.providers.get(prefix)
            if p:
                return (p.get("base_url", self.AIAND_BASE_URL),
                        p.get("api_key", self.AIAND_API_KEY), name)
        return (self.AIAND_BASE_URL, self.AIAND_API_KEY, model)


settings = Settings()
