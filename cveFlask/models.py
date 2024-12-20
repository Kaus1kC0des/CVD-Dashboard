from cveFlask import db

SCHEMA_NAME = "cveschema"


class CVE(db.Model):
    """
    Core CVE information model.

    Attributes:
        id (str): The unique identifier for the CVE.
        source_identifier (str): The source identifier for the CVE.
        published_date (datetime): The date when the CVE was published.
        last_modified_date (datetime): The date when the CVE was last modified.
        status (str): The status of the CVE.
        metrics (relationship): Relationship to the CVSSMetrics model.
        configurations (relationship): Relationship to the Configuration model.
        descriptions (relationship): Relationship to the Description model.
        references (relationship): Relationship to the Reference model.
        weaknesses (relationship): Relationship to the Weakness model.
    """
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
    """
    CVSS Scoring metrics model.

    Attributes:
        id (int): The unique identifier for the CVSS metrics.
        cve_id (str): The foreign key linking to the CVE model.
        version (str): The version of the CVSS.
        vector_string (str): The vector string of the CVSS.
        base_score (float): The base score of the CVSS.
        exploitability_score (float): The exploitability score of the CVSS.
        impact_score (float): The impact score of the CVSS.
        base_severity (str): The base severity of the CVSS.
        access_vector (str): The access vector of the CVSS.
        access_complexity (str): The access complexity of the CVSS.
        authentication (str): The authentication of the CVSS.
        confidentiality_impact (str): The confidentiality impact of the CVSS.
        integrity_impact (str): The integrity impact of the CVSS.
        availability_impact (str): The availability impact of the CVSS.
    """
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
    """
    CPE Configuration details model.

    Attributes:
        id (int): The unique identifier for the configuration.
        cve_id (str): The foreign key linking to the CVE model.
        criteria (str): The criteria for the configuration.
        match_criteria_id (str): The match criteria ID for the configuration.
        vulnerable (bool): Indicates if the configuration is vulnerable.
        operator (str): The operator for the configuration.
        negate (bool): Indicates if the configuration is negated.
    """
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
    """
    CVE Descriptions in different languages model.

    Attributes:
        id (int): The unique identifier for the description.
        cve_id (str): The foreign key linking to the CVE model.
        lang (str): The language of the description.
        value (str): The description text.
    """
    __tablename__ = 'description'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    lang = db.Column(db.String(10))
    value = db.Column(db.Text)


class Reference(db.Model):
    """
    CVE References model.

    Attributes:
        id (int): The unique identifier for the reference.
        cve_id (str): The foreign key linking to the CVE model.
        url (str): The URL of the reference.
        source (str): The source of the reference.
    """
    __tablename__ = 'reference'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    url = db.Column(db.String(500))
    source = db.Column(db.String(100))


class Weakness(db.Model):
    """
    CVE Weaknesses model.

    Attributes:
        id (int): The unique identifier for the weakness.
        cve_id (str): The foreign key linking to the CVE model.
        source (str): The source of the weakness.
        type (str): The type of the weakness.
        description (str): The description of the weakness.
    """
    __tablename__ = 'weakness'
    __table_args__ = {'schema': SCHEMA_NAME}

    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(30), db.ForeignKey(f'{SCHEMA_NAME}.cve.id'))
    source = db.Column(db.String(100))
    type = db.Column(db.String(50))
    description = db.Column(db.Text)