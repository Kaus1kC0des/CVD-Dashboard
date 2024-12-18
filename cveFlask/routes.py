from flask import render_template, url_for, redirect, request
from cveFlask import app
import pymysql
import os


connection = pymysql.connect(
        host=os.getenv("DB_URI"),
        user=os.getenv("DB_USERNAME"),
        password=os.getenv("DB_PWD"),
        database=os.getenv("DB_SCHEMA"),
    )
cursor = connection.cursor()
@app.route('/')
def index():
    cursor.execute(
        """
        SELECT * FROM cveSchema.cveDetails
        """
    )
    cves = cursor.fetchall()

    return render_template("home.html", cves=cves)

@app.route("/cve/<id>")
def cve(id):
    cursor.execute(
        "SELECT * FROM cveSchema.cveDetails WHERE id = %s",
        id
    )
    cve = cursor.fetchone()

    cursor.execute(
        """
        SELECT * FROM cveSchema.cveMetrics WHERE id = %s
        """,
        id
    )
    metrics = cursor.fetchall()


    cursor.execute(
        """
        SELECT * FROM cveSchema.cvssData WHERE id = %s
        """,
        id
    )
    cvssData = cursor.fetchall()

    if cve:
        return render_template("cve.html", cve=cve, metrics=metrics, cvssData=cvssData)
    return redirect(url_for('index'))



