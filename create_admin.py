#!/usr/bin/env python3
"""Script pour créer un utilisateur admin."""

import asyncio
import sys
sys.path.insert(0, '.')

from database import async_session
from models.user import User
from utils.security import hash_password
from sqlalchemy import select

async def create_admin():
    async with async_session() as db:
        # Vérifier si l'admin existe déjà
        result = await db.execute(select(User).where(User.email == 'admin@secure-ia.com'))
        existing = result.scalar_one_or_none()
        
        if existing:
            print("[INFO] Mise à jour de l'utilisateur admin existant...")
            existing.hashed_password = hash_password('Admin123!')
            existing.role = 'admin'
            existing.is_active = True
            existing.is_verified = True
            existing.full_name = 'Administrateur'
        else:
            print("[INFO] Création d'un nouvel utilisateur admin...")
            admin = User(
                email='admin@secure-ia.com',
                hashed_password=hash_password('Admin123!'),
                full_name='Administrateur',
                role='admin',
                is_active=True,
                is_verified=True,
                auth_provider='local',
                language='fr',
                monthly_analysis_count='0'
            )
            db.add(admin)
        
        await db.commit()
        print("[OK] Admin créé/mis à jour avec succès!")
        print("Email: admin@secure-ia.com")
        print("Mot de passe: Admin123!")

if __name__ == "__main__":
    asyncio.run(create_admin())
