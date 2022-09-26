const express = require('express')
const app = express()
const chai = require('chai')
const expect = chai.expect
chai.use(require('chai-http'))

// Body Parser Middleware
app.use(express.json()) // Allows us to handle raw JSON data
app.use(express.urlencoded({ extended: false })) // Allows us to handle url encoded data
const middleware = require('../../../src/middleware/middleware')
const cveMiddleware = require('../../../src/controller/cve.controller/cve.middleware')
app.use(middleware.createCtxAndReqUUID)

const mwCnaFixtures = require('./cnaMustOwnId.fixtures')
const errors = require('../../../src/middleware/error')
const error = new errors.MiddlewareError()

describe('Test cna must own Id middleware', () => {
  context('Positive Tests', function () {
    it('Requester Owns CVE ID, is a CNA and is not a Secretariat', function (done) {
      class RequesterOrg {
        async findOneByShortName () {
          return mwCnaFixtures.owningOrg
        }

        async isSecretariat () {
          return false
        }
      }
      class RequesterCveId {
        async findOneByCveId () {
          return mwCnaFixtures.cveDummy1
        }
      }

      app.route('/requester-owns-cveid-and-is-a-cna')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new RequesterOrg() },
            getCveIdRepository: () => { return new RequesterCveId() }
          }
          req.ctx.repositories = factory
          next()
        }, cveMiddleware.parsePostParams, middleware.cnaMustOwnID, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/requester-owns-cveid-and-is-a-cna')
        .set(mwCnaFixtures.owningOrgHeader)
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('message').and.to.be.a('string')
          expect(res.body.message).to.equal('Success! You have reached the target endpoint.')
          done()
        })
    })
  })

  context('Negative Tests', function () {
    it('Requester does not own CVE ID', function (done) {
      class RequesterOrg {
        async findOneByShortName () {
          return mwCnaFixtures.owningOrg
        }

        async isSecretariat () {
          return false
        }
      }
      class RequesterCveId {
        async findOneByCveId () {
          return mwCnaFixtures.cveDummy2
        }
      }

      app.route('/requester-does-not-own-cve-id')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new RequesterOrg() },
            getCveIdRepository: () => { return new RequesterCveId() }
          }
          req.ctx.repositories = factory
          next()
        }, cveMiddleware.parsePostParams, middleware.cnaMustOwnID, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/requester-does-not-own-cve-id')
        .set(mwCnaFixtures.owningOrg)
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.orgDoesNotOwnId()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })

    it('Requester did not provide a CVE ID', function (done) {
      class RequesterOrg {
        async findOneByShortName () {
          return mwCnaFixtures.owningOrg
        }

        async isSecretariat () {
          return false
        }
      }
      class RequesterCveId {
        async findOneByCveId () {
          return null
        }
      }

      app.route('/requester-did-not-provide-a-cve-id')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new RequesterOrg() },
            getCveIdRepository: () => { return new RequesterCveId() }
          }
          req.ctx.repositories = factory
          next()
        }, cveMiddleware.parsePostParams, middleware.cnaMustOwnID, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/requester-did-not-provide-a-cve-id')
        .set(mwCnaFixtures.owningOrg)
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.orgDoesNotOwnId()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })
  })
})
