import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.reporting.report_generator import ReportGenerator
from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter()
report_generator = ReportGenerator()


@router.get("/emails/{email_id}/pdf")
@router.get("/{email_id}/pdf")
async def generate_pdf_report(email_id: UUID, db: AsyncSession = Depends(get_db)):
    """Generate a forensic threat intelligence report in PDF format."""
    try:
        pdf_bytes = await report_generator.generate_pdf(email_id=email_id, db=db)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="forensic_report_{email_id}.pdf"'
            },
        )
    except ValueError as e:
        logger.warning(f"Forensic PDF report generation failed: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error generating forensic PDF report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error generating forensic PDF report")


@router.get("/emails/{email_id}/json")
@router.get("/{email_id}/json")
async def get_json_report(email_id: UUID, db: AsyncSession = Depends(get_db)):
    """Generate a structured forensic threat intelligence report in JSON format."""
    try:
        report_data = await report_generator.generate_json(email_id=email_id, db=db)
        return JSONResponse(content=report_data)
    except ValueError as e:
        logger.warning(f"Forensic JSON report generation failed: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error generating forensic JSON report: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error generating forensic JSON report")


@router.get("/emails/{email_id}/preview")
@router.get("/{email_id}/preview")
async def preview_report(email_id: UUID, db: AsyncSession = Depends(get_db)):
    """Generate an HTML preview of the forensic threat intelligence report."""
    try:
        html_content = await report_generator.generate_preview(email_id=email_id, db=db)
        return HTMLResponse(content=html_content, media_type="text/html")
    except ValueError as e:
        logger.warning(f"Forensic HTML report preview failed: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error generating forensic HTML report preview: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error generating forensic HTML preview")


