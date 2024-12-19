from cveFlask import db

SCHEMA_NAME = "cveschema"


class cveDetails(db.Model):
    __tablename__ = 'cveDetails'
    __table_args__ = {'schema': "cveschema"}

    cve_id = db.Column(db.String(30), primary_key=True, nullable=False)
    identifier = db.Column(db.String(50), nullable=False)
    published_date = db.Column(db.DateTime, nullable=False)
    last_modified_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return f"cveDetails('{self.cve_id}', '{self.identifier}', '{self.published_date}', '{self.last_modified_date}', '{self.status}')"

class cveMetrics(db.Model):
    __tablename__ = 'cveMetrics'
    __table_args__ = {'schema': "cveschema"}

    cve_id = db.Column(db.String(30), db.ForeignKey(f"{SCHEMA_NAME}.cveDetails.cve_id"), primary_key=True, nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(10), nullable=False)
    vector_string = db.Column(db.String(50), nullable=False)


    def __repr__(self):
        return f"cveMetrics('{self.cve_id}', '{self.description}', '{self.severity}', '{self.vector_string}')"


class cvssData(db.Model):
    __tablename__= 'cvssData'
    __table_args__ = {'schema': "cveschema"}

    cve_id = db.Column(db.String(30), db.ForeignKey(f"{SCHEMA_NAME}.cveDetails.cve_id"), primary_key=True, nullable=False)
    access_vector = db.Column(db.String(10), nullable=False)
    access_complexity = db.Column(db.String(10), nullable=False)
    authentication = db.Column(db.String(10), nullable=False)
    confidentiality_impact = db.Column(db.String(10), nullable=False)
    integrity_impact = db.Column(db.String(10), nullable=False)
    availability_impact = db.Column(db.String(10), nullable=False)


    def __repr__(self):
        return f"cvssData('{self.cve_id}', '{self.access_vector}', '{self.access_complexity}', '{self.authentication}', '{self.confidentiality_impact}', '{self.integrity_impact}', '{self.availability_impact}')"