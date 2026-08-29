import asyncio
from app.database import AsyncSessionLocal
from sqlalchemy import select
from app.models.email_case import Email
from app.core.pipeline import AnalysisPipeline

async def main():
    pipeline = AnalysisPipeline()
    async with AsyncSessionLocal() as session:
        emails_res = await session.execute(select(Email))
        emails = emails_res.scalars().all()
        print(f"Re-analyzing {len(emails)} emails in database with clean restored code...")

        for email in emails:
            try:
                res = await pipeline.run(email.id, db=session)
                print(f"[OK] Re-analyzed Email: {email.id}")
            except Exception as e:
                print(f"Error reanalyzing email {email.id}: {e}")

        await session.commit()
    print("All database analysis results have been refreshed successfully!")

if __name__ == "__main__":
    asyncio.run(main())
