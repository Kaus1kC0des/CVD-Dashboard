import os
import requests
from dotenv import load_dotenv
from cveFlask import app, db
from cveFlask.models import cveDetails, cveMetrics, cvssData
from tqdm.cli import tqdm

load_dotenv()

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
idx = 0
resultsPerPage = 2000

def write_chunks_to_db(vulnerabilities):
    with app.app_context():
        for i in tqdm(range(len(vulnerabilities))):
            vul = vulnerabilities[i]['cve']
            metrics = vul.get("metrics", dict())
            cvssMetricsV2 = metrics.get("cvssMetricV2", [dict()])[0]
            cvssDataDict = cvssMetricsV2.get("cvssData", dict())

            index = vul['id']
            source = vul.get("sourceIdentifier")
            published = " ".join(vul.get("published").strip().split("T"))
            lastModified = " ".join(vul.get("lastModified").strip().split("T"))
            vulStatus = vul.get("vulnStatus")
            description = [i.get('value', '') for i in vul.get("descriptions") if i.get('lang') == 'en'][0]

            try:
                # Insert into cveDetails
                cve_detail = cveDetails(
                    cve_id=index,
                    identifier=source,
                    published_date=published,
                    last_modified_date=lastModified,
                    status=vulStatus
                )
                db.session.add(cve_detail)

                # Insert into cveMetrics
                cve_metric = cveMetrics(
                    cve_id=index,
                    description=description,
                    severity=cvssDataDict.get("baseSeverity", ""),
                    vector_string=cvssDataDict.get("vectorString", "")
                )
                db.session.add(cve_metric)

                # Insert into cvssData
                cvss_data = cvssData(
                    cve_id=index,
                    access_vector=cvssDataDict.get("accessVector", ""),
                    access_complexity=cvssDataDict.get("accessComplexity", ""),
                    authentication=cvssDataDict.get("authentication", ""),
                    confidentiality_impact=cvssDataDict.get("confidentialityImpact", ""),
                    integrity_impact=cvssDataDict.get("integrityImpact", ""),
                    availability_impact=cvssDataDict.get("availabilityImpact", "")
                )
                db.session.add(cvss_data)

                db.session.commit()
            except Exception as e:
                print(e)
                db.session.rollback()


while idx < 137:
    CHUNK_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={resultsPerPage}&startIndex={idx * resultsPerPage}"
    response = requests.get(CHUNK_URL)
    if response.status_code != 200:
        print(response.status_code)
        idx -= resultsPerPage
    else:
        vulnerabilities = response.json()['vulnerabilities']
        print(f"Current Iteration: {idx}")
        write_chunks_to_db(vulnerabilities)

    idx += 1