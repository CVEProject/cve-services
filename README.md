# CVE-API

![CodeQL](https://github.com/CVEProject/cve-services/workflows/CodeQL/badge.svg)

## Table of contents

* [Project](#project)
* [Contributing](#contributing)
   * [Security](#security)
      * [Reporting a Vulnerability](#reporting-a-vulnerability)
* [Development](#development)
   * [Technologies](#technologies)
   * [Style Guidelines](#style-guidelines)
   * [Directory Layout](#directory-layout)
   * [Setup](#setup)
   * [API Documentation](#api-documentation)
   * [Unit Testing](#unit-testing)

## The CVE Services Project

This repository contains services that support the [CVE Program's mission](https://www.cve.org/About/Overview) to "identify, define, and catalog publicly disclosed cybersecurity vulnerabilities."

There are many ways one can assist:

### OSS Contributor

Developers can contribute code directly. Getting started can be as fast as choosing an issue on our [board](https://github.com/CVEProject/cve-services/issues?q=is%3Aissue+is%3Aopen).

Please read our [contributor's guide](https://github.com/CVEProject/cve-services/blob/dev/CONTRIBUTING.md) for more details. We welcome all contributions!

### Working Groups

The CVE project operates as multiple focused working groups. Visit the CVE Website [working groups page](https://www.cve.org/ProgramOrganization/WorkingGroups) for more information.

### Security

#### Reporting a Vulnerability

>**Warning**
>Do not put vulnerability information in a GitHub issue.

Please consult our [SECURITY.md](https://github.com/CVEProject/cve-services/blob/dev/SECURITY.md) for specific instructions on reporting a vulnerability that exists in the CVE Services.

## Development

### Technologies

This project uses or depends on software from

- [NodeJS](https://nodejs.org/)
- [Express](https://github.com/expressjs)
- [MongoDB for locally run instances](https://www.mongodb.com/)
- [Mongoose.js](https://mongoosejs.com)

### Style Guidelines

This project follows the [JavaScript Standard Style](https://github.com/standard/standard).

### Setup

#### Docker

See the Docker README found in the repo here: https://github.com/CVEProject/cve-services/blob/dev/docker/README.md

#### Local Development

>**Warning**
>
>DO NOT use the dev configuration on a public network. The dev environment includes credentials to enable rapid development and is not secure for public deployment.

1. Install required node modules

This assumes `node` 16.14.2 and the latest `npm` are installed.

```sh
cd cve-services
npm install
```

2. Setup and start MongoDB locally

Install MongoDB locally

- https://docs.mongodb.com/manual/administration/install-community/

Download MongoDB Compass (MongoDB GUI)

- https://www.mongodb.com/download-center/compass

Create a `cve_dev` database in Compass. The collections will be automatically created when the API starts storing documents.

You can populate the database with test data using:

```sh
npm run populate:dev
```

3. Start the node application

In order to start a dev environment:

```sh
npm run start:dev
```


### API Documentation

API documentation is generated using [swagger-autogen](https://github.com/davibaltar/swagger-autogen) which ensures that we keep the API specification up to date with any major changes to API routes. Extra information for each API route is defined as a comment in the `index.js` files under the respective controller and all request and response schemas are stored under the `schemas` folder served up by `schemas.controller`.

To ensure you are using the correct API specification the following endpoints can be used:
- [Test Instance](https://cveawg-test.mitre.org/api-docs/)
- [Production](https://cveawg.mitre.org/api-docs/)

Note: The specification file stored in GitHub will only be correct for that branch; there could be differences between branches and production.

If you are developer and want to test changes to the API specification you can generate a specification in one of two ways:

1. Preferred

When you start your local development server using `npm run start:dev` the specification file will be generated. Subsequent changes require reloading the server.

2. Manual

You can use `npm run swagger-autogen` to generate a new specification file.


### Unit Testing

This project uses the following for unit testing

- https://mochajs.org/
- https://www.chaijs.com/

In order to run the unit tests:

```sh
npm run start:test
```
