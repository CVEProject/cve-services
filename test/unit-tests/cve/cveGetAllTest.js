const express = require('express')
const app = express()
const chai = require('chai')
const expect = chai.expect
chai.use(require('chai-http'))

// Body Parser Middleware
app.use(express.json()) // Allows us to handle raw JSON data
app.use(express.urlencoded({ extended: false })) // Allows us to handle url encoded data
const middleware = require('../../../src/middleware/middleware')
app.use(middleware.createCtxAndReqUUID)

const getConstants = require('../../../src/constants').getConstants
const cveList = require('../../schemas/5.0/cveRecordList.json')

const cveFixtures = require('./mockObjects.cve')
const cveController = require('../../../src/controller/cve.controller/cve.controller')
const cveParams = require('../../../src/controller/cve.controller/cve.middleware')

describe('Testing the GET /cve endpoint in Cve Controller', () => {
  context('Positive Tests', () => {
    it('JSON schema v5.0 returned: The secretariat gets a list of non-paginated cve records', (done) => {
      const itemsPerPage = 500

      class MyCvePositiveTests {
        async aggregatePaginate () {
          const res = {
            itemsList: cveList,
            itemCount: cveList.length,
            itemsPerPage: itemsPerPage,
            currentPage: 1,
            pageCount: 1,
            pagingCounter: 1,
            hasPrevPage: false,
            hasNextPage: false,
            prevPage: null,
            nextPage: null
          }

          return res
        }
      }

      app.route('/cve-get-all-records-positive-tests-non-empty-non-paginated')
        .get((req, res, next) => {
          const factory = {
            getCveRepository: () => { return new MyCvePositiveTests() }
          }
          req.ctx.repositories = factory
          next()
        }, cveParams.parseGetParams, cveController.CVE_GET_FILTERED)

      chai.request(app)
        .get('/cve-get-all-records-positive-tests-non-empty-non-paginated')
        .set(cveFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('cveRecords').and.to.be.a('array').and.to.have.lengthOf(cveList.length)
          expect(res.body).to.not.have.property('totalCount')
          expect(res.body).to.not.have.property('itemsPerPage')
          expect(res.body).to.not.have.property('pageCount')
          expect(res.body).to.not.have.property('currentPage')
          expect(res.body).to.not.have.property('prevPage')
          expect(res.body).to.not.have.property('nextPage')
          res.body.cveRecords.forEach(obj => {
            const CONSTANTS = getConstants()
            // only cve records with state 'PUBLISHED' or 'REJECTED' are stored in the db
            expect(obj).to.have.nested.property('cveMetadata.state').and.to.be.oneOf([CONSTANTS.CVE_STATES.PUBLISHED, CONSTANTS.CVE_STATES.REJECTED])
          })
          done()
        })
    })

    it('JSON schema v5.0 returned: The secretariat gets a list of paginated cve records with "page" query param undefined', (done) => {
      const itemsPerPage = 3

      class MyCvePositiveTests {
        async aggregatePaginate () {
          const res = {
            itemsList: [cveList[0], cveList[1], cveList[2]],
            itemCount: cveList.length,
            itemsPerPage: itemsPerPage,
            currentPage: 1,
            pageCount: 2,
            pagingCounter: 1,
            hasPrevPage: false,
            hasNextPage: true,
            prevPage: null,
            nextPage: 2
          }

          return res
        }
      }

      app.route('/cve-get-all-records-positive-tests-non-empty-paginated')
        .get((req, res, next) => {
          const factory = {
            getCveRepository: () => { return new MyCvePositiveTests() }
          }
          req.ctx.repositories = factory
          // temporary fix for #920: force pagnation
          req.TEST_PAGINATOR_LIMIT = itemsPerPage
          next()
        }, cveParams.parseGetParams, cveController.CVE_GET_FILTERED)

      chai.request(app)
        .get('/cve-get-all-records-positive-tests-non-empty-paginated')
        .set(cveFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          const CONSTANTS = getConstants()

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('cveRecords').and.to.be.a('array').and.to.have.lengthOf(itemsPerPage)
          expect(res.body).to.have.property('totalCount').and.to.equal(cveList.length)
          expect(res.body).to.have.property('itemsPerPage').and.to.equal(itemsPerPage)
          expect(res.body).to.have.property('pageCount').and.to.equal(2)
          expect(res.body).to.have.property('currentPage').and.to.equal(1)
          expect(res.body).to.have.property('prevPage').and.to.equal(null)
          expect(res.body).to.have.property('nextPage').and.to.equal(2)
          res.body.cveRecords.forEach(obj => {
            // only cve records with state 'PUBLISHED' or 'REJECTED' are stored in the db
            expect(obj).to.have.nested.property('cveMetadata.state').and.to.be.oneOf([CONSTANTS.CVE_STATES.PUBLISHED, CONSTANTS.CVE_STATES.REJECTED])
          })
          done()
        })
    })

    it('JSON schema v5.0 returned: The secretariat gets a list of paginated cve records with "page" query param defined', (done) => {
      const itemsPerPage = 3

      class MyCvePositiveTests {
        async aggregatePaginate () {
          const res = {
            itemsList: [cveList[3], cveList[4]],
            itemCount: cveList.length,
            itemsPerPage: itemsPerPage,
            currentPage: 2,
            pageCount: 2,
            pagingCounter: 1,
            hasPrevPage: true,
            hasNextPage: false,
            prevPage: 1,
            nextPage: null
          }

          return res
        }
      }

      app.route('/cve-get-all-records-positive-tests-non-empty-paginated-2')
        .get((req, res, next) => {
          const factory = {
            getCveRepository: () => { return new MyCvePositiveTests() }
          }
          req.ctx.repositories = factory
          // temporary fix for #920: force pagnation
          req.TEST_PAGINATOR_LIMIT = itemsPerPage
          next()
        }, cveParams.parseGetParams, cveController.CVE_GET_FILTERED)

      chai.request(app)
        .get('/cve-get-all-records-positive-tests-non-empty-paginated-2?page=2')
        .set(cveFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('cveRecords').and.to.be.a('array').and.to.have.lengthOf(2)
          expect(res.body).to.have.property('totalCount').and.to.equal(cveList.length)
          expect(res.body).to.have.property('itemsPerPage').and.to.equal(itemsPerPage)
          expect(res.body).to.have.property('pageCount').and.to.equal(2)
          expect(res.body).to.have.property('currentPage').and.to.equal(2)
          expect(res.body).to.have.property('prevPage').and.to.equal(1)
          expect(res.body).to.have.property('nextPage').and.to.equal(null)
          res.body.cveRecords.forEach(obj => {
            const CONSTANTS = getConstants()
            // only cve records with state 'PUBLISHED' or 'REJECTED' are stored in the db
            expect(obj).to.have.nested.property('cveMetadata.state').and.to.be.oneOf([CONSTANTS.CVE_STATES.PUBLISHED, CONSTANTS.CVE_STATES.REJECTED])
          })
          done()
        })
    })

    it('JSON schema v5.0 returned: The secretariat gets an empty list of cve records because there are no cve records in the database', (done) => {
      const itemsPerPage = 500

      class MyCvePositiveTests {
        async aggregatePaginate () {
          const res = {
            itemsList: [],
            itemCount: 0,
            itemsPerPage: itemsPerPage,
            currentPage: 1,
            pageCount: 1,
            pagingCounter: 1,
            hasPrevPage: false,
            hasNextPage: false,
            prevPage: null,
            nextPage: null
          }

          return res
        }
      }

      app.route('/cve-get-all-records-positive-tests-empty')
        .get((req, res, next) => {
          const factory = {
            getCveRepository: () => { return new MyCvePositiveTests() }
          }
          req.ctx.repositories = factory
          next()
        }, cveParams.parseGetParams, cveController.CVE_GET_FILTERED)

      chai.request(app)
        .get('/cve-get-all-records-positive-tests-empty')
        .set(cveFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('cveRecords').and.to.be.a('array').and.to.have.lengthOf(0)
          expect(res.body).to.not.have.property('totalCount')
          expect(res.body).to.not.have.property('itemsPerPage')
          expect(res.body).to.not.have.property('pageCount')
          expect(res.body).to.not.have.property('currentPage')
          expect(res.body).to.not.have.property('prevPage')
          expect(res.body).to.not.have.property('nextPage')
          done()
        })
    })

    it('Filter by reserved state', (done) => {
      class MyCvePositiveTests {
        async filterByState () {
          const res = {
            state: 'RESERVED'
          }

          return res
        }
      }

      app.route('/cve-get-all-records-by-reserved-state')
        .get((req, res, next) => {
          const factory = {
            getCveRepository: () => { return new MyCvePositiveTests() }
          }
          req.ctx.repositories = factory
          next()
        }, cveParams.parseGetParams, cveController.CVE_GET_FILTERED)

      chai.request(app)
        .get('/cve-get-all-records-positive-tests-non-empty-non-paginated')
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          res.body.cveRecords.forEach(obj => {
            const CONSTANTS = getConstants()
            // only cve records with state 'PUBLISHED' or 'REJECTED' are stored in the db
            expect(obj).to.have.nested.property('cveMetadata.state').and.to.be.oneOf([CONSTANTS.CVE_STATES.RESERVED, CONSTANTS.CVE_STATES.REJECTED, CONSTANTS.CVE_STATES.PUBLISHED])
          })
          done()
        })
    })

    it('Filter by published state', (done) => {
      class MyCvePositiveTests {
        async filterByState () {
          const res = {
            state: 'PUBLISHED'
          }

          return res
        }
      }

      app.route('/cve-get-all-records-by-reserved-state')
        .get((req, res, next) => {
          const factory = {
            getCveRepository: () => { return new MyCvePositiveTests() }
          }
          req.ctx.repositories = factory
          next()
        }, cveParams.parseGetParams, cveController.CVE_GET_FILTERED)

      chai.request(app)
        .get('/cve-get-all-records-positive-tests-non-empty-non-paginated')
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          res.body.cveRecords.forEach(obj => {
            const CONSTANTS = getConstants()
            // only cve records with state 'PUBLISHED' or 'REJECTED' are stored in the db
            expect(obj).to.have.nested.property('cveMetadata.state').and.to.be.oneOf([CONSTANTS.CVE_STATES.RESERVED, CONSTANTS.CVE_STATES.REJECTED, CONSTANTS.CVE_STATES.PUBLISHED])
          })
          done()
        })
    })

    it('Filter by rejected state', (done) => {
      class MyCvePositiveTests {
        async filterByState () {
          const res = {
            state: 'REJECTED'
          }

          return res
        }
      }

      app.route('/cve-get-all-records-by-reserved-state')
        .get((req, res, next) => {
          const factory = {
            getCveRepository: () => { return new MyCvePositiveTests() }
          }
          req.ctx.repositories = factory
          next()
        }, cveParams.parseGetParams, cveController.CVE_GET_FILTERED)

      chai.request(app)
        .get('/cve-get-all-records-positive-tests-non-empty-non-paginated')
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          res.body.cveRecords.forEach(obj => {
            const CONSTANTS = getConstants()
            // only cve records with state 'PUBLISHED' or 'REJECTED' are stored in the db
            expect(obj).to.have.nested.property('cveMetadata.state').and.to.be.oneOf([CONSTANTS.CVE_STATES.RESERVED, CONSTANTS.CVE_STATES.REJECTED, CONSTANTS.CVE_STATES.PUBLISHED])
          })
          done()
        })
    })
  })
})
