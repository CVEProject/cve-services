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

const mwCnaFixtures = require('./onlyCnas.fixtures')
const errors = require('../../../src/middleware/error')
const error = new errors.MiddlewareError()

describe('Test only CNA middleware', () => {
  context('Positive Tests', function () {
    it('Requester is a CNA', function (done) {
      class OrgOnlyCnasOrgCnaPass {
        async findOneByShortName () {
          return mwCnaFixtures.cnaOrg
        }
      }

      app.route('/only-cnas-org-cna-passes')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlyCnasOrgCnaPass() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlyCnas, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/only-cnas-org-cna-passes')
        .set(mwCnaFixtures.cnaHeaders)
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

    it('Requester is a CNA and a secretariat', function (done) {
      class OrgOnlyCnasOrgCnaSecretariatPass {
        async findOneByShortName () {
          return mwCnaFixtures.secretariatAndCnaOrg
        }
      }

      app.route('/only-cnas-org-cna-and-secretariat-passes')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlyCnasOrgCnaSecretariatPass() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlyCnas, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/only-cnas-org-cna-and-secretariat-passes')
        .set(mwCnaFixtures.secretariatAndCnaHeaders)
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

    // This test will change with the implementation of Root CNAs, as the burden of reserving IDs
    // on behalf of other organizations transfers to Roots. Secretariat will then step back.
    it('Requester is a secretariat but not a CNA', function (done) {
      class OrgOnlyCnasOrgSecretariatPass {
        async findOneByShortName () {
          return mwCnaFixtures.secretariatOrg
        }
      }

      app.route('/only-cnas-org-secretariat-passes')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlyCnasOrgSecretariatPass() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlyCnas, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/only-cnas-org-secretariat-passes')
        .set(mwCnaFixtures.secretariatHeaders)
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
    it('Requester is not a CNA or a secretariat', function (done) {
      class OrgOnlyCnasOrgNotCnaReject {
        async findOneByShortName () {
          return mwCnaFixtures.notCnaOrg
        }
      }

      app.route('/only-cnas-org-not-cna-rejected')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlyCnasOrgNotCnaReject() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlyCnas, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/only-cnas-org-not-cna-rejected')
        .set(mwCnaFixtures.notCnaHeaders)
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.cnaOnly()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })

    it('Requester organization shortname is not valid', function (done) {
      class OrgOnlyCnasOrgNull {
        async findOneByShortName () {
          return null
        }
      }

      app.route('/only-cnas-org-equals-null')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlyCnasOrgNull() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlyCnas, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/only-cnas-org-equals-null')
        .set(mwCnaFixtures.notCnaHeaders)
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(404)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.cnaDoesNotExist(mwCnaFixtures.notCnaHeaders['CVE-API-ORG'])
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })
  })
})
