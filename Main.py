from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from Router import Router

App = FastAPI(
	title='CVE Tracker API',
	description='Lightweight vulnerability tracking system'
)

App.include_router(Router)

@App.get('/', include_in_schema=False)
async def root():
	return RedirectResponse(url='/docs')