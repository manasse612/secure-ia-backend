"""
Script de migration : Ajouter la colonne active_session_token à la table users.
Exécuter une seule fois : python add_session_token_column.py
"""
import psycopg2
from config import settings

def migrate():
    # Extraire l'URL sync pour psycopg2
    db_url = settings.database_url_sync
    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    cur = conn.cursor()

    # Vérifier si la colonne existe déjà
    cur.execute("""
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'active_session_token'
    """)
    if cur.fetchone():
        print("La colonne active_session_token existe deja.")
    else:
        cur.execute("ALTER TABLE users ADD COLUMN active_session_token VARCHAR(255)")
        print("Colonne active_session_token ajoutee avec succes.")

    cur.close()
    conn.close()

if __name__ == "__main__":
    migrate()
