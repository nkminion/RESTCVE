from sqlalchemy import Column, String, Text, Numeric
from Datasbase import Base

class CVE(Base):
    __tablename__ = "cves"

    cveid = Column(String(50), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    descr = Column(Text, nullable=False)
    cvss_score = Column(Numeric(4, 2), nullable=False)
    target_os = Column(String(100))
    target_arch = Column(String(50))
    status = Column(String(50), default="Open", index=True)
    notes = Column(Text)