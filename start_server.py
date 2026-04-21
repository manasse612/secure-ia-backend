#!/usr/bin/env python
"""
Script de démarrage avec redémarrage automatique.
Peu importe l'erreur, le serveur redémarre automatiquement.
"""
import subprocess
import sys
import time
import os

PORT = os.environ.get("PORT", "8004")
HOST = os.environ.get("HOST", "0.0.0.0")
RESTART_DELAY = 3  # secondes entre chaque redémarrage
DOCKER_CONTAINER = "secure-ia-db"

def start_docker():
    """Démarrer le conteneur Docker PostgreSQL."""
    try:
        print("🐳 Démarrage du conteneur Docker...")
        result = subprocess.run(
            ["docker", "start", DOCKER_CONTAINER],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            print(f"✅ Conteneur {DOCKER_CONTAINER} démarré")
            print("⏳ Attente de l'initialisation de la base de données (3s)...")
            time.sleep(3)
            return True
        else:
            print(f"⚠️  Erreur Docker: {result.stderr}")
            return False
    except FileNotFoundError:
        print("❌ Docker n'est pas installé ou pas dans le PATH")
        return False
    except Exception as e:
        print(f"⚠️  Erreur lors du démarrage Docker: {e}")
        return False

def start_server():
    """Démarrer uvicorn avec redémarrage automatique."""
    # Démarrer Docker d'abord
    start_docker()
    
    while True:
        print(f"\n{'='*60}")
        print(f"🚀 Démarrage Secure IA sur http://{HOST}:{PORT}")
        print(f"{'='*60}")
        
        try:
            # Lancer uvicorn avec reload pour détection de changements
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "uvicorn",
                    "main:app",
                    "--host", HOST,
                    "--port", PORT,
                    "--reload",  # Redémarre auto sur changements de code
                    "--reload-delay", "1",
                    "--log-level", "info"
                ],
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            
            # Attendre que le processus se termine
            exit_code = process.wait()
            
            if exit_code != 0:
                print(f"\n⚠️  Serveur arrêté avec code {exit_code}")
                print(f"⏳ Redémarrage dans {RESTART_DELAY} secondes...")
                time.sleep(RESTART_DELAY)
            else:
                print("\n✅ Arrêt normal")
                break
                
        except KeyboardInterrupt:
            print("\n🛑 Arrêt demandé par l'utilisateur")
            if 'process' in locals():
                process.terminate()
            break
        except Exception as e:
            print(f"\n💥 Erreur critique: {e}")
            print(f"⏳ Redémarrage dans {RESTART_DELAY} secondes...")
            time.sleep(RESTART_DELAY)

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║           Secure IA - Serveur Auto-Redémarrage               ║
║                                                              ║
║  Ce script redémarre automatiquement le serveur en cas      ║
║  d'erreur. Peu importe le crash, il revient toujours !      ║
╚══════════════════════════════════════════════════════════════╝
    """)
    start_server()
