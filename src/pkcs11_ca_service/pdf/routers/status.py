"""status router"""

from typing import Any
from fastapi import APIRouter
from pkcs11_ca_service.pdf.routers.utils.status import healthy
from pkcs11_ca_service.pdf.models import StatusReply
from pkcs11_ca_service.pdf.context import ContextRequest, ContextRequestRoute

status_router = APIRouter(route_class=ContextRequestRoute, prefix="/status")


@status_router.get("/healthy", response_model=StatusReply)
def endpoint_healthy(req: ContextRequest) -> Any:
    """Endpoint for status/healthy"""
    return healthy(req=req)
