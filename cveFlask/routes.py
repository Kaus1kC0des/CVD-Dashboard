from flask import render_template, url_for, redirect, request, abort
from cveFlask import app
from cveFlask.models import CVE, CVSSMetrics, Configuration, Description, Reference, Weakness
import os

ITEMS_PER_PAGE = 50

@app.route("/")
@app.route("/page/<int:page>")
def index(page=1):
    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort', 'published_date')

    query = CVE.query

    if search_query:
        query = query.filter(
            (CVE.id.ilike(f'%{search_query}%')) |
            (CVE.source_identifier.ilike(f'%{search_query}%'))
        )

    if sort_by == 'published_date':
        query = query.order_by(CVE.published_date.asc())
    elif sort_by == 'last_modified_date':
        query = query.order_by(CVE.last_modified_date.asc())
    elif sort_by == 'status':
        query = query.order_by(CVE.status.asc())

    try:
        pagination = query.paginate(
            page=page,
            per_page=ITEMS_PER_PAGE,
            error_out=True
        )
        return render_template(
            'home.html',
            cves=pagination.items,
            pagination=pagination,
            current_page=page,
            total_pages=pagination.pages,
            search_query=search_query,
            sort_by=sort_by
        )
    except Exception as e:
        abort(404)

@app.route("/cve/<cve_id>")
def cve(cve_id):
    cve = CVE.query.filter(CVE.id == cve_id).first()
    cvss_metrics = CVSSMetrics.query.filter(CVSSMetrics.cve_id == cve_id).first()
    configurations = Configuration.query.filter(Configuration.cve_id == cve_id).all()
    descriptions = Description.query.filter(Description.cve_id == cve_id, Description.lang == 'en').first()
    references = Reference.query.filter(Reference.cve_id == cve_id).all()
    weaknesses = Weakness.query.filter(Weakness.cve_id == cve_id).all()
    return render_template(
        'cve.html',
        cve=cve,
        metrics=cvss_metrics,
        configurations=configurations,
        descriptions=descriptions,
        references=references,
        weaknesses=weaknesses
    )