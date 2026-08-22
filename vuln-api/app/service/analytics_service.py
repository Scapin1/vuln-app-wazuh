# app/services/analytics_service.py
from datetime import datetime, time, timedelta, timezone
from typing import Optional

from fastapi import HTTPException


def get_date_filters(period: str, date: Optional[str], model_col):
    now = datetime.now(timezone.utc)
    if period == "24h":
        return [model_col >= (now - timedelta(hours=24))]
    elif period == "7d":
        return [model_col >= (now - timedelta(days=7))]
    elif period == "30d":
        return [model_col >= (now - timedelta(days=30))]
    elif period == "day":
        if not date:
            raise HTTPException(status_code=400, detail={"error": "Falta parámetro date"})
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
            start_of_day = datetime.combine(target_date, time.min).replace(tzinfo=timezone.utc)
            return [model_col >= start_of_day, model_col < start_of_day + timedelta(days=1)]
        except ValueError:
            raise HTTPException(status_code=400, detail={"error": "Formato de fecha inválido"})
    elif period == "all":
        return []
    else:
        raise HTTPException(status_code=400, detail={"error": "Periodo no válido"})
