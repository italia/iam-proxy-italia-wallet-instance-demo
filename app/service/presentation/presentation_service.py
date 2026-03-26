import logging
from ..base.base_service import BaseService
from app.store import AppState

logger = logging.getLogger(__name__)

class PresentationService(BaseService):

    def __init__(self, app_state: AppState):
        logger.debug(f"Entering method: __init__. Params []")
        super().__init__(app_state)

