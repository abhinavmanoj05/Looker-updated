import os
from neo4j import GraphDatabase
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    MODEL_STORAGE_PATH: str = os.getenv("MODEL_STORAGE_PATH", "intel_self_trainer.pkl")

settings = Settings()

class GraphDatabaseConnection:
    def __init__(self):
        self._driver = None

    def _ensure_driver(self):
        if self._driver is None and settings.NEO4J_PASSWORD:
            self._driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                max_connection_pool_size=50
            )
        return self._driver

    def close(self):
        if self._driver is not None:
            self._driver.close()

    def get_session(self):
        driver = self._ensure_driver()
        if driver is None:
            return None
        return driver.session()

db_graph = GraphDatabaseConnection()
