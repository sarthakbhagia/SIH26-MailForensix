import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.user import User, UserRole
from app.models.organization import Organization
from app.core.security import get_password_hash

logger = logging.getLogger(__name__)

async def seed_default_admin(db: AsyncSession):
    """Create default admin user if no users exist"""
    try:
        result = await db.execute(select(User))
        existing_users = result.scalars().all()

        if not existing_users:
            # Create default organization
            org_result = await db.execute(select(Organization).where(Organization.slug == "default"))
            default_org = org_result.scalar_one_or_none()
            
            if not default_org:
                default_org = Organization(
                    name="Default Organization",
                    slug="default",
                    is_active=True
                )
                db.add(default_org)
                await db.flush()

            admin_email = "admin@mailforensix.local"
            admin_password = "admin123"  # Change this in production!

            admin_user = User(
                email=admin_email,
                hashed_password=get_password_hash(admin_password),
                role=UserRole.admin,
                org_id=default_org.id
            )

            db.add(admin_user)
            await db.commit()

            logger.info(f"✓ Default admin user created: {admin_email}")
            logger.info(f"  Password: {admin_password}")
            logger.info("  ⚠️  CHANGE THIS PASSWORD IN PRODUCTION!")
        else:
            logger.debug("Users already exist, skipping default admin seed")

    except Exception as e:
        logger.error(f"Failed to seed default admin: {e}")
        await db.rollback()
