from pkcs11_ca_service.common.helpers import unix_ts
from pkcs11_ca_service.pdf.models import StatusReply
from pkcs11_ca_service.pdf.context import ContextRequest


def healthy(req: ContextRequest) -> StatusReply:
    """sign a PDF"""
    req.app.logger.info(msg="Check for healthy")

    return StatusReply(
        status="STATUS_OK",
    )
