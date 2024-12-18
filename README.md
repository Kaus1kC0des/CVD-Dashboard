Still building the workspace index, response may be less accurate.

# CVD Dashboard

## Overview

The CVD Dashboard is a web application designed to consume CVE (Common Vulnerabilities and Exposures) information from the NVD (National Vulnerability Database) API, store it in a database, and provide a user-friendly interface to view and filter the CVE details. The application is built using Flask, a lightweight WSGI web application framework in Python, and uses MySQL as the database.

## Features

1. **Consume CVE Information**: Retrieve CVE data from the NVD API and store it in a MySQL database.
2. **Data Cleansing & De-duplication**: Ensure data quality by applying data cleansing and de-duplication techniques.
3. **Periodic Synchronization**: Synchronize CVE details into the database periodically in batch mode.
4. **API Endpoints**: Provide APIs to read and filter CVE details by various parameters.
5. **UI Visualization**: Visualize CVE data in a user-friendly interface using HTML, CSS, and JavaScript.
6. **Pagination and Sorting**: Implement server-side pagination and sorting for efficient data retrieval.
7. **API Documentation**: Provide detailed documentation for each API operation.
8. **Unit Testing**: Write well-defined unit test cases for all functionalities.

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
    Create a 

.env

 file in the root directory with the following content:
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

- **GET /cves/list**
    - Retrieves a list of CVE details.
    - Query Parameters:
        - 

resultsPerPage

: Number of results per page (default: 10).
        - `page`: Page number (default: 1).

- **GET /cve/<id>**
    - Retrieves details of a specific CVE by ID.

### Filter CVE Details

- **GET /cves/filter**
    - Filters CVE details by various parameters.
    - Query Parameters:
        - `cve_id`: Filter by CVE ID.
        - `year`: Filter by year.
        - 

score

: Filter by CVE score.
        - `last_modified`: Filter by last modified date (in days).

## UI Pages

### Home Page

- **Route**: `/`
- **Description**: Displays a list of CVE details with pagination and sorting options.

### CVE Details Page

- **Route**: `/cve/<id>`
- **Description**: Displays detailed information about a specific CVE.

## Data Synchronization

### Fetch CVE Data

- **Script**: 

fetch.py


- **Description**: Fetches CVE data from the NVD API and stores it in the database.

### Fetch CVE Metrics

- **Script**: 

fetchMetrics.py


- **Description**: Fetches CVE metrics from the NVD API and stores it in the database.

## Unit Testing

- **Framework**: `unittest`
- **Description**: Write unit tests for all functionalities to ensure code quality and reliability.

## Best Practices

- Follow PEP 8 coding standards.
- Use environment variables for sensitive information.
- Write clear and concise code with proper documentation.
- Ensure data quality through data cleansing and de-duplication.
- Implement error handling and logging for debugging and monitoring.


## Contact

For any questions or inquiries, please contact [Kausik D](mailto:kausikdevanathan@gmail.com).