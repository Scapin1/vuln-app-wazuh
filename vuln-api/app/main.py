# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import analytics, auth, crud, rol_assets, roles, sync, user_assets, wazuh
from .routers.analytics import get_date_filters

CONNECTION_NOT_FOUND = "Conexión no encontrada"

app = FastAPI(title="Vulnerability Aggregator API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(wazuh.router)
app.include_router(analytics.router)
app.include_router(sync.router)
app.include_router(crud.router)
app.include_router(roles.router)
app.include_router(user_assets.router)
app.include_router(rol_assets.router)
