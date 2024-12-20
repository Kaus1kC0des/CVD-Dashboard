import logging
from datetime import datetime

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter, Retry
from tqdm import tqdm

from cveFlask import app, db
from cveFlask.models import CVE, CVSSMetrics, Configuration, Description, Reference, Weakness

# Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
load_dotenv()

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000
CHUNK_SIZE = 500
MAX_RETRIES = 5


def extract_cvss_metrics(metrics):
    """
    Extract CVSS metrics from vulnerability data.

    Args:
        metrics (dict): The metrics data from the vulnerability.

    Returns:
        CVSSMetrics: An instance of the CVSSMetrics model with extracted data.
    """
    if not metrics:
        return None

    cvss_v2 = metrics.get("cvssMetricV2", [])
    if isinstance(cvss_v2, dict):
        cvss_v2 = [cvss_v2]
    if not cvss_v2:
        return None

    metric_data = cvss_v2[0]
    cvss_data = metric_data.get("cvssData", {})

    return CVSSMetrics(
        version=cvss_data.get("version"),
        vector_string=cvss_data.get("vectorString"),
        base_score=cvss_data.get("baseScore"),
        exploitability_score=metric_data.get("exploitabilityScore"),
        impact_score=metric_data.get("impactScore"),
        base_severity=metric_data.get("baseSeverity"),
        access_vector=cvss_data.get("accessVector"),
        access_complexity=cvss_data.get("accessComplexity"),
        authentication=cvss_data.get("authentication"),
        confidentiality_impact=cvss_data.get("confidentialityImpact"),
        integrity_impact=cvss_data.get("integrityImpact"),
        availability_impact=cvss_data.get("availabilityImpact")
    )


def process_vulnerability(vuln_data):
    """
    Process a single vulnerability.

    Args:
        vuln_data (dict): The vulnerability data.

    Returns:
        CVE: An instance of the CVE model with processed data, or None if processing fails.
    """
    try:
        cve_data = vuln_data.get('cve', {})
        if not cve_data:
            logger.error("Missing 'cve' key in vulnerability data")
            return None

        # Create CVE instance
        cve = CVE(
            id=cve_data['id'],
            source_identifier=cve_data.get('sourceIdentifier'),
            published_date=datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00')),
            last_modified_date=datetime.fromisoformat(cve_data['lastModified'].replace('Z', '+00:00')),
            status=cve_data.get('vulnStatus')
        )

        # Process CVSS metrics
        metrics_data = cve_data.get('metrics', {})
        if metrics_data:
            cvss_metrics = extract_cvss_metrics(metrics_data)
            if cvss_metrics:
                cve.metrics = [cvss_metrics]

        # Process configurations
        configurations_data = cve_data.get('configurations', [])
        for config in configurations_data:
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    configuration = Configuration(
                        cve_id=cve.id,
                        criteria=cpe_match.get('criteria'),
                        match_criteria_id=cpe_match.get('matchCriteriaId'),
                        vulnerable=cpe_match.get('vulnerable', False),
                        operator=node.get('operator'),
                        negate=node.get('negate', False)
                    )
                    cve.configurations.append(configuration)

        # Process descriptions
        descriptions_data = cve_data.get('descriptions', [])
        for desc in descriptions_data:
            description = Description(
                cve_id=cve.id,
                lang=desc.get('lang'),
                value=desc.get('value')
            )
            cve.descriptions.append(description)

        # Process references
        references_data = cve_data.get('references', [])
        for ref in references_data:
            reference = Reference(
                cve_id=cve.id,
                url=ref.get('url'),
                source=ref.get('source')
            )
            cve.references.append(reference)

        # Process weaknesses
        weaknesses_data = cve_data.get('weaknesses', [])
        for weak in weaknesses_data:
            for desc in weak.get('description', []):
                weakness = Weakness(
                    cve_id=cve.id,
                    source=weak.get('source'),
                    type=weak.get('type'),
                    description=desc.get('value')
                )
                cve.weaknesses.append(weakness)

        return cve
    except Exception as e:
        logger.error(f"Error processing vulnerability: {str(e)}")
        return None


def write_chunk_to_db(vulnerabilities):
    """
    Write a chunk of vulnerabilities to the database.

    Args:
        vulnerabilities (list): List of vulnerability data to be written to the database.
    """
    with app.app_context():
        try:
            cve_list = []
            metrics_list = []
            configurations_list = []
            descriptions_list = []
            references_list = []
            weaknesses_list = []

            for vuln in vulnerabilities:
                processed_vuln = process_vulnerability(vuln)
                if processed_vuln is None:
                    continue
                cve_list.append(processed_vuln)
                metrics_list.extend(processed_vuln.metrics)
                configurations_list.extend(processed_vuln.configurations)
                descriptions_list.extend(processed_vuln.descriptions)
                references_list.extend(processed_vuln.references)
                weaknesses_list.extend(processed_vuln.weaknesses)

            def to_dict(instance):
                return {c.name: getattr(instance, c.name) for c in instance.__table__.columns}

            if cve_list:
                db.session.bulk_insert_mappings(CVE, [to_dict(cve) for cve in cve_list])

            if metrics_list:
                db.session.bulk_insert_mappings(CVSSMetrics, [to_dict(metric) for metric in metrics_list])

            if configurations_list:
                db.session.bulk_insert_mappings(Configuration, [to_dict(config) for config in configurations_list])

            if descriptions_list:
                db.session.bulk_insert_mappings(Description, [to_dict(desc) for desc in descriptions_list])

            if references_list:
                db.session.bulk_insert_mappings(Reference, [to_dict(ref) for ref in references_list])

            if weaknesses_list:
                db.session.bulk_insert_mappings(Weakness, [to_dict(weak) for weak in weaknesses_list])

            db.session.commit()
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            db.session.rollback()


def fetch_vulnerabilities(start_index):
    """
    Fetch vulnerabilities from the API with retry.

    Args:
        start_index (int): The starting index for fetching vulnerabilities.

    Returns:
        list: List of vulnerabilities fetched from the API, or None if the request fails.
    """
    url = f"{BASE_URL}/?resultsPerPage={RESULTS_PER_PAGE}&startIndex={start_index}"

    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )

    with requests.Session() as session:
        session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
        try:
            response = session.get(url, timeout=60)
            response.raise_for_status()
            return response.json()['vulnerabilities']
        except Exception as e:
            logger.error(f"API request failed: {str(e)}")
            return None


def main():
    """
    Main execution function to fetch and process vulnerabilities.
    """
    idx = 0
    max_pages = 137

    with tqdm(total=max_pages, desc="Total Progress") as pbar:
        while idx < max_pages:
            start_index = idx * RESULTS_PER_PAGE
            logger.info(f"Fetching vulnerabilities starting at index {start_index}")

            vulnerabilities = fetch_vulnerabilities(start_index)
            if not vulnerabilities:
                logger.error(f"Failed to fetch data for index {start_index}, retrying...")
                continue

            # Process in chunks with progress bar
            chunks = [vulnerabilities[i:i + CHUNK_SIZE]
                      for i in range(0, len(vulnerabilities), CHUNK_SIZE)]

            # Process each chunk sequentially
            with tqdm(total=len(chunks), desc=f"Processing Chunks {idx}/{max_pages}") as chunk_pbar:
                for chunk in chunks:
                    write_chunk_to_db(chunk)
                    chunk_pbar.update(1)

            idx += 1
            pbar.update(1)


if __name__ == "__main__":
    main()
