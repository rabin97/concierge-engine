"""Channel providers. 'console' providers log instead of sending, so the whole flow runs offline."""
import logging
import uuid

import httpx

from app.config import settings
from app.services.notifications.templates import Template

log = logging.getLogger("notifications")


class ProviderError(Exception):
    pass


class ConsoleWhatsApp:
    def send(self, to_phone: str, tpl: Template, ctx: dict) -> str:
        log.info("[WHATSAPP -> %s] template=%s params=%s", to_phone, tpl.wa_name, tpl.wa_params(ctx))
        return f"console-wa-{uuid.uuid4()}"


class MetaWhatsApp:
    """WhatsApp Cloud API: POST /{phone_number_id}/messages with an approved template."""

    def send(self, to_phone: str, tpl: Template, ctx: dict) -> str:
        url = (f"https://graph.facebook.com/{settings.whatsapp_api_version}/"
               f"{settings.whatsapp_phone_number_id}/messages")
        body = {
            "messaging_product": "whatsapp",
            "to": to_phone.lstrip("+"),
            "type": "template",
            "template": {
                "name": tpl.wa_name,
                "language": {"code": "en"},
                "components": [{"type": "body",
                                "parameters": [{"type": "text", "text": v} for v in tpl.wa_params(ctx)]}],
            },
        }
        r = httpx.post(url, json=body, timeout=10.0,
                       headers={"Authorization": f"Bearer {settings.whatsapp_token}"})
        if r.status_code >= 400:
            raise ProviderError(f"whatsapp {r.status_code}: {r.text[:300]}")
        return r.json()["messages"][0]["id"]


class ConsoleEmail:
    def send(self, to_email: str, tpl: Template, ctx: dict) -> str:
        log.info("[EMAIL -> %s] subject=%r", to_email, tpl.email_subject(ctx))
        return f"console-email-{uuid.uuid4()}"


class SesEmail:
    def __init__(self) -> None:
        import boto3

        self.client = boto3.client("sesv2", region_name=settings.aws_region)

    def send(self, to_email: str, tpl: Template, ctx: dict) -> str:
        kwargs = dict(
            FromEmailAddress=settings.ses_from_address,
            Destination={"ToAddresses": [to_email]},
            Content={"Simple": {"Subject": {"Data": tpl.email_subject(ctx)},
                                "Body": {"Text": {"Data": tpl.email_body(ctx)}}}},
        )
        if settings.ses_configuration_set:
            kwargs["ConfigurationSetName"] = settings.ses_configuration_set
        try:
            return self.client.send_email(**kwargs)["MessageId"]
        except Exception as e:  # botocore ClientError
            raise ProviderError(str(e)) from e


def whatsapp_provider():
    return MetaWhatsApp() if settings.whatsapp_provider == "meta" else ConsoleWhatsApp()


def email_provider():
    return SesEmail() if settings.email_provider == "ses" else ConsoleEmail()
