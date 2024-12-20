from flask import render_template, request, abort
from cveFlask import app
from cveFlask.models import CVE, CVSSMetrics, Configuration, Description, Reference, Weakness

@app.route("/")
@app.route("/page/<int:page>")
def index(page=1):
    """
    Renders the home page with a list of CVEs, supporting search, sort, and pagination functionality.

    Args:
        page (int): The page number for pagination. Defaults to 1.

    Returns:
        str: Rendered HTML template for the home page.

    Query Parameters:
        search (str): Search query to filter CVEs by ID or source identifier.
        sort (str): Sort parameter to order CVEs by 'published_date', 'last_modified_date', or 'status'.
        per_page (int): Number of results to display per page.
    """
    # Get search, sort, and per_page parameters from the request
    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort', 'published_date')
    per_page = int(request.args.get('per_page', 10))

    # Base query for CVEs
    query = CVE.query

    # Apply search filter if search query is provided
    if search_query:
        query = query.filter(
            (CVE.id.ilike(f'%{search_query}%')) |
            (CVE.source_identifier.ilike(f'%{search_query}%'))
        )

    # Apply sorting based on the sort parameter
    if sort_by == 'published_date':
        query = query.order_by(CVE.published_date.asc())
    elif sort_by == 'last_modified_date':
        query = query.order_by(CVE.last_modified_date.asc())
    elif sort_by == 'status':
        query = query.order_by(CVE.status.asc())

    try:
        # Paginate the query results
        pagination = query.paginate(
            page=page,
            per_page=per_page,
            error_out=True
        )
        # Render the home page template with the paginated CVEs
        return render_template(
            'home.html',
            cves=pagination.items,
            pagination=pagination,
            current_page=page,
            total_pages=pagination.pages,
            search_query=search_query,
            sort_by=sort_by,
            per_page=per_page,
            total_records=pagination.total
        )
    except Exception as e:
        # Abort with a 404 error if pagination fails
        abort(404)

@app.route("/cve/<cve_id>")
def cve(cve_id):
    """
    Renders the detailed view of a specific CVE.

    Args:
        cve_id (str): The unique identifier of the CVE.

    Returns:
        str: Rendered HTML template for the CVE detail page.
    """
    # Query the CVE by its ID
    cve = CVE.query.filter(CVE.id == cve_id).first()
    # Query related CVSS metrics
    cvss_metrics = CVSSMetrics.query.filter(CVSSMetrics.cve_id == cve_id).first()
    # Query related configurations
    configurations = Configuration.query.filter(Configuration.cve_id == cve_id).all()
    # Query the description in English
    descriptions = Description.query.filter(Description.cve_id == cve_id, Description.lang == 'en').first()
    # Query related references
    references = Reference.query.filter(Reference.cve_id == cve_id).all()
    # Query related weaknesses
    weaknesses = Weakness.query.filter(Weakness.cve_id == cve_id).all()
    # Render the CVE detail page template with the queried data
    return render_template(
        'cve.html',
        cve=cve,
        metrics=cvss_metrics,
        configurations=configurations,
        descriptions=descriptions,
        references=references,
        weaknesses=weaknesses
    )