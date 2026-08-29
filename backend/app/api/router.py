from fastapi import APIRouter
from app.api import ingest, analysis, cases, alerts, reports, dashboard, graph, auth

api_router = APIRouter(prefix="/api")

api_router.include_router(auth.router)
api_router.include_router(ingest.router, prefix="/emails", tags=["emails"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
api_router.include_router(cases.router, prefix="/cases", tags=["cases"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(graph.router, prefix="/graph", tags=["graph"])
