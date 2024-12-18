# CVD Dashboard

## Overview

The CVD Dashboard is a web application designed to consume CVE (Common Vulnerabilities and Exposures) information from the NVD (National Vulnerability Database) API, store it in a database, and provide a user-friendly interface to view and filter the CVE details. The application is built using Flask, a lightweight WSGI web application framework in Python, and uses MySQL as the database.

## Features

1. **Consume CVE Information**: Retrieved CVE data from the NVD API and store it in a MySQL database.
2. **Data Cleansing & De-duplication**: Ensured data quality by applying data cleansing and de-duplication techniques.
3. **Periodic Synchronization**: Synchronized CVE details into the database periodically in batch mode.
4. **API Endpoints**: Provides APIs to read and filter CVE details by various parameters.
5. **UI Visualization**: Visualizes CVE data in a user-friendly interface using HTML, CSS, and JavaScript.
6. **Pagination and Sorting**: Implemented server-side pagination and sorting for efficient data retrieval.
7. **API Documentation**: Provided detailed documentation for each API operation.


## Directory Structure

```
.
├── app.py
├── cveFlask
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── static
│   │   └── main.css
│   └── templates
│       ├── cve.html
│       ├── home.html
│       └── layout.html
├── fetch.py
├── fetchMetrics.py
├── poetry.lock
└── pyproject.toml
```

## Setup Instructions

### Prerequisites

- Python 3.10
- MySQL
- Poetry (for dependency management)

### Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/Kaus1kC0des/CVD-Dashboard.git
    cd CVD-Dashboard
    ```

2. **Install dependencies**:
    ```sh
    poetry install
    ```

3. **Set up environment variables**:
    Create a .env file in the root directory with the following content:
    ```env
    SECRET_KEY=<your-secret-key>
    SQLALCHEMY_DATABASE_URI=mysql+pymysql://<username>:<password>@<host>/<database>
    DB_URI=<your-db-uri>
    DB_USERNAME=<your-db-username>
    DB_PWD=<your-db-password>
    DB_SCHEMA=<your-db-schema>
    ```

4. **Initialize the database**:
    ```sh
    python -m flask db init
    python -m flask db migrate
    python -m flask db upgrade
    ```

### Running the Application

1. **Start the Flask application**:
    ```sh
    python app.py
    ```

2. **Access the application**:
    Open your web browser and navigate to `http://localhost:5000`.

## API Endpoints

### Retrieve CVE Details

- **GET /**
    - Retrieves a list of all available CVE details.

- **GET /cve/{id}**
    - Retrieves details of a specific CVE by ID.


## UI Pages

### Home Page

- **Route**: `/`
- **Description**: Displays a list of CVE details.

### CVE Details Page

- **Route**: `/cve/<id>`
- **Description**: Displays detailed information about a specific CVE, given its `id`.

## Data Synchronization

### Fetch CVE Data

- **Script**: fetch.py

- **Description**: Fetches CVE data from the NVD API and stores it in the database.

### Fetch CVE Metrics

- **Script**: fetchMetrics.py
- **Description**: Fetches CVE metrics from the NVD API and stores it in the database.


## Contact

For any questions or inquiries, please feel free to reach out to me.