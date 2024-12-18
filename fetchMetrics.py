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
idx = 5
resultsPerPage = 2000
parsed = 0

def write_chunks_to_db(vulnerabilities):
    for i in range(len(vulnerabilities)):
        vul = vulnerabilities[i]['cve']
        metrics = vul.get("metrics",dict())
        cvssMetricsV2 = metrics.get("cvssMetricV2",dict())
        if type(cvssMetricsV2) is dict:
            cvssData = cvssMetricsV2.get("cvssData", dict())
        else:
            cvssMetricsV2 = cvssMetricsV2[0]
            cvssData = cvssMetricsV2.get("cvssData", dict())
        index = vul['id']

        severity = cvssMetricsV2.get("baseSeverity")
        score = cvssData.get("baseScore")
        vectorString = cvssData.get("vectorString")

        accessVector = cvssData.get("accessVector")
        accessComplexity = cvssData.get("accessComplexity")
        authentication = cvssData.get("authentication")
        confidentialityImpact = cvssData.get("confidentialityImpact")
        integrityImpact = cvssData.get("integrityImpact")
        availabilityImpact = cvssData.get("availabilityImpact")
        try:
            cursor.execute(
                """
                INSERT INTO cveSchema.cveMetrics(id, severity, score, vectorString)
                VALUES (%s, %s, %s, %s)
                """,
                (index, severity, score, vectorString)
            )
            cursor.execute(
                """
                INSERT INTO cveSchema.cvssData(id, accessVector, accessComplexity, authentication, confImpact, integrityImpact, availabilityImpact)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (index, accessVector, accessComplexity, authentication, confidentialityImpact, integrityImpact, availabilityImpact)
            )
            connection.commit()

        except Exception as e:
            print(e)
    connection.commit()



while idx<137:
    CHUNK_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={resultsPerPage}&startIndex={idx*resultsPerPage}"
    response = requests.get(CHUNK_URL)
    if response.status_code != 200:
        print(response.status_code)
        idx -= resultsPerPage
    else:
        vulnerabilities = response.json()['vulnerabilities']
        write_chunks_to_db(vulnerabilities)

    idx += 1