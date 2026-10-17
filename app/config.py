from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    NEO4J_URI: str = ""
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = ""

    AIAND_API_KEY: str = ""
    AIAND_BASE_URL: str = "https://api.aiand.example/v1"

    ATTACKER_MODEL: str = "deepseek-chat"
    DEFENDER_MODEL: str = "kimi-k2"
    REPORT_MODEL: str = "kimi-k2"

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
