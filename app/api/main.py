import logging

from fastapi import FastAPI

from app.api.routes import router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title="AI Household Concierge Engine",
    version="0.1.0",
    description="Prompt -> validated task tree -> durable workflow -> WhatsApp/email notifications",
)
app.include_router(router)
