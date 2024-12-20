## Setup and Installation

### Prerequisites

- Python 3.8+
- PostgreSQL
- `pip` (Python package installer)

### Installation Steps

1. **Clone the repository**:
    ```sh
    git clone https://github.com/Kaus1kC0des/cve-dashboard.git
    cd cve-dashboard
    ```

2. **Create and activate a virtual environment**:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the required packages**:
    ```sh
    pip install -r requirements.txt
    ```

4. **Set up the environment variables**:
   Create a `.env` file in the root directory and add the following variables:
    ```env
    SECRET_KEY=your_secret_key
    SQLALCHEMY_DATABASE_URI=postgresql://username:password@localhost/dbname
    DB_SCHEMA=your_db_schema
    ```

5. **Initialize the database**:
    ```sh
    flask db init
    flask db migrate -m "Initial migration."
    flask db upgrade
    ```

6. **Fetch and populate CVE data**:
    ```sh
    python fetchData.py
    ```

7. **Run the Flask application**:
    ```sh
    flask run
    ```

## Usage

### Accessing the Dashboard

Open your web browser and navigate to `http://127.0.0.1:5000/` to access the CVE Dashboard.

### Searching and Sorting

- Use the search bar to find CVEs by ID or source identifier.
- Use the sort dropdown to sort CVEs by published date, last modified date, or status.

### Viewing CVE Details

Click on a CVE ID to view detailed information about the CVE, including metrics, configurations, descriptions, references, and weaknesses.

## Contributing

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Acknowledgements

- [NVD API](https://nvd.nist.gov/vuln/data-feeds) for providing the CVE data.
- [Flask](https://flask.palletsprojects.com/) for the web framework.
- [Bootstrap](https://getbootstrap.com/) for the frontend framework.