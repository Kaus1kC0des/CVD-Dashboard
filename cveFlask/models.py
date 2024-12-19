from cveFlask import db

SCHEMA_NAME = "cveschema"

class CVE(db.Model):
    """Core CVE information"""
    __tablename__ = 'cve'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.String(30), primary_key=True)
    source_identifier = db.Column(db.String(50), nullable=False)
    published_date = db.Column(db.DateTime, nullable=False)
    last_modified_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False)

    # Relationships
    metrics = db.relationship('CVSSMetrics', backref='cve', lazy=True)
    configurations = db.relationship('Configuration', backref='cve', lazy=True)
    descriptions = db.relationship('Description', backref='cve', lazy=True)
    references = db.relationship('Reference', backref='cve', lazy=True)
    weaknesses = db.relationship('Weakness', backref='cve', lazy=True)

class CVSSMetrics(db.Model):
    """CVSS Scoring metrics"""
    __tablename__ = 'cvss_metrics'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    version = db.Column(db.String(10))
    vector_string = db.Column(db.String(100))
    base_score = db.Column(db.Float)
    exploitability_score = db.Column(db.Float)
    impact_score = db.Column(db.Float)
    base_severity = db.Column(db.String(20))
    
    # CVSS Base Metrics
    access_vector = db.Column(db.String(20))
    access_complexity = db.Column(db.String(20))
    authentication = db.Column(db.String(20))
    confidentiality_impact = db.Column(db.String(20))
    integrity_impact = db.Column(db.String(20))
    availability_impact = db.Column(db.String(20))

class Configuration(db.Model):
    """CPE Configuration details"""
    __tablename__ = 'configuration'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    criteria = db.Column(db.String(255))
    match_criteria_id = db.Column(db.String(50))
    vulnerable = db.Column(db.Boolean, default=False)
    operator = db.Column(db.String(10))
    negate = db.Column(db.Boolean, default=False)

class Description(db.Model):
    """CVE Descriptions in different languages"""
    __tablename__ = 'description'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    lang = db.Column(db.String(10))
    value = db.Column(db.Text)

class Reference(db.Model):
    """CVE References"""
    __tablename__ = 'reference'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    url = db.Column(db.String(500))
    source = db.Column(db.String(100))

class Weakness(db.Model):
    """CVE Weaknesses"""
    __tablename__ = 'weakness'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    source = db.Column(db.String(100))
    type = db.Column(db.String(50))
    description = db.Column(db.Text)