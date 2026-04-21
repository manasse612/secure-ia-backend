# === Configuration de la connexion à la base de données PostgreSQL ===
# Utilise SQLAlchemy en mode asynchrone pour de meilleures performances

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from config import settings


# Créer le moteur de connexion asynchrone à PostgreSQL
engine = create_async_engine(
    settings.database_url,
    echo=settings.debug,  # Afficher les requêtes SQL en mode debug
    pool_size=20,          # Nombre de connexions dans le pool
    max_overflow=10,       # Connexions supplémentaires si le pool est plein
)

# Créer une fabrique de sessions asynchrones
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Garder les objets accessibles après commit
)


# Classe de base pour tous les modèles de la base de données
class Base(DeclarativeBase):
    pass


async def get_db():
    """
    Générateur de sessions de base de données.
    Utilisé comme dépendance dans les routes FastAPI.
    Ouvre une session, la fournit, puis la ferme automatiquement.
    """
    async with async_session() as session:
        try:
            yield session
            await session.commit()  # Valider les changements
        except Exception:
            await session.rollback()  # Annuler en cas d'erreur
            raise
        finally:
            await session.close()  # Toujours fermer la session


async def init_db():
    """
    Initialiser la base de données.
    Crée toutes les tables définies dans les modèles.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
