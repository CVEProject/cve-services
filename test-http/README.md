# CVE Services Endpoint Testing

**Warning**: do not point these tests at production!!!

This portion of the repository contains HTTP tests written using Python `requests`, and `pytest`. They can be run against any instantiation of the REST API by updating `test-http/docker/.docker-env` accordingly. The REST API must have a backing MongoDb database. Tests should not be run against production, since they do update and delete data. Some tests assume that the MITRE organization exists and is the secretariat.

## Usage

The following will run tests against an existing instance of the CPS and services API, given that the docker environment manifest is updated with valid credentials.

```sh
cd test-http

# Copy default credentials
# Edit these to point at the desired endpoint
cp docker/.docker-env.example docker/.docker-env

# Run the testing container
docker-compose --file docker/docker-compose.yml up --build

# Run the tests
docker exec -it demon pytest src/
```

## External Documentation

The automated functional testing framework relies on the following technologies which developers interface with directly:

* [Docker](https://docs.docker.com/)
* [Python](https://www.python.org/doc/)
* [Pytest](https://docs.pytest.org/en/stable/)
* [Requests](https://requests.readthedocs.io/en/master/)
