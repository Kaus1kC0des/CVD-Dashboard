import os
import requests
import json
import pymysql
from dotenv import load_dotenv
load_dotenv()


try:
    connection = pymysql.connect(
        host=os.getenv("DB_URI"),
        user=os.getenv("DB_USERNAME"),
        password=os.getenv("DB_PWD"),
        database=os.getenv("DB_SCHEMA"),
    )
    cursor = connection.cursor()
    print("Connection established")
except Exception as e:
    print(e)



BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
idx = 0
resultsPerPage = 2000
parsed = 0

def write_chunks_to_db(vulnerabilities):
    for i in range(len(vulnerabilities)):
        vul = vulnerabilities[i]['cve']
        metrics = vul.get("metrics",dict())
        cvssMetricsV2 = metrics.get("cvssMetricV2",dict())[0]
        cvssData = cvssMetricsV2.get("cvssData", dict())

        index = vul['id']
        source = vul.get("sourceIdentifier")
        published = " ".join(vul.get("published").strip().split("T"))
        lastModified = " ".join(vul.get("lastModified").strip().split("T"))
        vulStatus = vul.get("vulnStatus")
        description = [i.get('value','') for i in vul.get("descriptions") if i.get('lang')=='en'][0]



        try:
            cursor.execute(
                """
                INSERT INTO cveSchema.cveDetails(id, sourceId, published, lastModified, vulStatus, description) 
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (index, source, published, lastModified, vulStatus, description)
            )

            connection.commit()
        except Exception as e:
            print(e)







while idx<137:
    CHUNK_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={resultsPerPage}&startIndex={idx*resultsPerPage}"
    response = requests.get(CHUNK_URL)
    if response.status_code != 200:
        print(response.status_code)
        idx -= resultsPerPage
    else:
        vulnerabilities = response.json()['vulnerabilities']
        write_chunks_to_db(vulnerabilities)

    print(f"Parsed {parsed} of {idx*resultsPerPage} vulnerabilities")
    parsed += len(response.json()['vulnerabilities'])
    idx += 1
