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

const mwFixtures = require('./onlySecretariat.fixtures')
const getConstants = require('../../../src/constants').getConstants
const errors = require('../../../src/middleware/error')
const error = new errors.MiddlewareError()

describe('Test only Secretariat middleware', () => {
  context('Positive Tests', function () {
    it('User is a secretariat', function (done) {
      class OrgOnlySecretariatPass {
        async isSecretariat () {
          return true
        }
      }

      app.route('/only-secretariat-pass')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlySecretariatPass() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlySecretariat, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/only-secretariat-pass')
        .set(mwFixtures.secretariatHeaders)
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
    it('User is not a secretariat', function (done) {
      class OrgOnlySecretariatReject {
        async isSecretariat () {
          return false
        }
      }

      app.route('/only-secretariat-reject')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlySecretariatReject() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlySecretariat, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      const testHeaders = Object.assign({}, mwFixtures.secretariatHeaders)
      const CONSTANTS = getConstants()

      testHeaders[CONSTANTS.AUTH_HEADERS.USER] = mwFixtures.notSecretariatUser.username
      testHeaders[CONSTANTS.AUTH_HEADERS.ORG] = mwFixtures.notSecretariatOrg.short_name

      chai.request(app)
        .post('/only-secretariat-reject')
        .set(testHeaders)
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.secretariatOnly()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })
  })
})
