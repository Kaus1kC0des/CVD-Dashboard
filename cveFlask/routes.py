from flask import render_template, url_for, redirect, request
from cveFlask import app
from cveFlask.models import CVE, CVSSMetrics, Configuration, Description, Reference, Weakness
import os


@app.route("/")
def index():
    cves = CVE.query.all()
    return render_template('home.html', cves=cves)


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