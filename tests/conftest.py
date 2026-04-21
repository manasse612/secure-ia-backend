# === Configuration des tests pytest ===
# Ajoute le répertoire backend au PYTHONPATH pour que les imports fonctionnent

import sys
import os

# Ajouter le répertoire parent (backend/) au chemin Python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
