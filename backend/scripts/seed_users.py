import asyncio
from app.database import engine, Base, AsyncSessionLocal
from sqlalchemy import select
from app.models.user import User, UserRole
from app.models.organization import Organization
from app.core.security import get_password_hash

async def main():
    # Ensure tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Check / create org
        org_res = await session.execute(select(Organization).where(Organization.slug == "default"))
        org = org_res.scalar_one_or_none()
        if not org:
            org = Organization(name="Default Organization", slug="default", is_active=True)
            session.add(org)
            await session.flush()

        # Check / create users
        for email in ["admin@mailforensix.local", "admin@mailforensix.com"]:
            user_res = await session.execute(select(User).where(User.email == email))
            existing = user_res.scalar_one_or_none()
            if not existing:
                u = User(
                    email=email,
                    hashed_password=get_password_hash("admin123"),
                    role=UserRole.admin,
                    org_id=org.id,
                    is_active=True
                )
                session.add(u)
                print(f"Created user: {email}")
            else:
                print(f"User exists: {email}")

        await session.commit()
        print("Database user check complete!")

if __name__ == "__main__":
    asyncio.run(main())
