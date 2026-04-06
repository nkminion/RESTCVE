drop table if exists cves;
create table if not exists cves(
	cveid VARCHAR(50) primary key,
	title VARCHAR(255) not null,
	descr TEXT not null,
	cvss_score NUMERIC(4,2) not null,
	target_os VARCHAR(100),
	target_arch VARCHAR(50),
	status VARCHAR(50) default 'open',
	notes TEXT
);

CREATE INDEX CVESTATIDX ON cves(STATUS);
CREATE INDEX CVETARIDX ON cves(TARGETOS);