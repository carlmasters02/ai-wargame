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

    GAME_SEED: int = 42
    MAX_TURNS: int = 20
    PATH_METRIC_IMPL: str = "python"  # "python" (fast, default) | "cypher" (showcase)

    @property
    def neo4j_enabled(self) -> bool:
        return bool(self.NEO4J_URI and self.NEO4J_PASSWORD)

    @property
    def aiand_enabled(self) -> bool:
        return bool(self.AIAND_API_KEY)


settings = Settings()
