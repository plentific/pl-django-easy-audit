import logging

from easyaudit.models import CRUDEvent, LoginEvent, RequestEvent

logger = logging.getLogger(__name__)


class ModelBackend:
    def request(self, request_info):
        return RequestEvent.objects.create(**request_info)

    def crud(self, crud_info):
        logger.warning("AUDIT BACKEND: Received crud_info: %s", crud_info)

        # Debug: Check if UUID fields are in the data
        if "authenticated_user_uuid" in crud_info:
            logger.warning(
                "AUDIT BACKEND: authenticated_user_uuid present: %s",
                crud_info["authenticated_user_uuid"],
            )
        else:
            logger.error("AUDIT BACKEND: authenticated_user_uuid MISSING from crud_info")

        if "user_uuid" in crud_info:
            logger.warning("AUDIT BACKEND: user_uuid present: %s", crud_info["user_uuid"])
        else:
            logger.error("AUDIT BACKEND: user_uuid MISSING from crud_info")

        created_event = CRUDEvent.objects.create(**crud_info)

        # Debug: Check what was actually saved
        logger.warning(
            "AUDIT BACKEND: Created event %s with authenticated_user_uuid=%s, user_uuid=%s",
            created_event.id,
            created_event.authenticated_user_uuid,
            created_event.user_uuid,
        )

        return created_event

    def login(self, login_info):
        return LoginEvent.objects.create(**login_info)
