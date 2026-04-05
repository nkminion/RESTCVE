from fastapi import APIRouter,Depends,HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List,Optional
import Model
import Schema
from Datasbase import GetDB

Router = APIRouter()

@Router.post('/cves', response_model=Schema.CVEResponse)
async def CreateCVE(Payload: Schema.CVECreate, DB: AsyncSession = Depends(GetDB)):
	DupRows = await DB.get(Model.CVE, Payload.cveid)
	if (DupRows):
		raise HTTPException(status_code=400, detail='CVE Exists')
	NewCVE = Model.CVE(**Payload.model_dump())
	DB.add(NewCVE)
	await DB.commit()
	return NewCVE

@Router.get('/cves', response_model=List[Schema.CVEResponse])
async def GetCVEs(Status: Optional[str] = None, DB: AsyncSession = Depends(GetDB)):
	Query = select(Model.CVE)
	if Status is not None:
		Query = Query.where(Model.CVE.status == Status)
	ResRows = await DB.execute(Query)
	return ResRows.scalars().all()

@Router.patch('/cves/{cveid}', response_model=Schema.CVEResponse)
async def UpdateCVE(cveid: str, Payload: Schema.CVEUpdate, DB: AsyncSession = Depends(GetDB)):
	ExistingRow = await DB.get(Model.CVE, cveid)
	if not ExistingRow:
		raise HTTPException(status_code=404, detail='Not Found')
	Changes = Payload.model_dump(exclude_unset=True)
	for k,v in Changes.items():
		setattr(ExistingRow, k, v)
	await DB.commit()
	return ExistingRow

@Router.delete('/cves/{cveid}')
async def DeleteCVE(cveid: str, DB: AsyncSession = Depends(GetDB)):
	ExistingRow = await DB.get(Model.CVE, cveid)
	if not ExistingRow:
		raise HTTPException(status_code=404, detail='Not Found')
	await DB.delete(ExistingRow)
	await DB.commit()

	return cveid