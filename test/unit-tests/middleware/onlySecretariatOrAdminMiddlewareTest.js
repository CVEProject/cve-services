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

const mwSecretariatOrAdminFixtures = require('./onlySecretariatOrAdmin.fixtures')
const errors = require('../../../src/middleware/error')
const error = new errors.MiddlewareError()

class OrgOnlySecretariatOrAdmin {
  async isSecretariat (shortname) {
    if (shortname === mwSecretariatOrAdminFixtures.secretariatOrg.short_name) {
      return true
    }

    return false
  }
}

class UserOnlySecretariatOrAdmin {
  async isAdmin (username, shortname) {
    if (username === mwSecretariatOrAdminFixtures.secretariatUser.username && shortname === mwSecretariatOrAdminFixtures.secretariatOrg.short_name) {
      return false
    } else if (username === mwSecretariatOrAdminFixtures.regularUser.username && shortname === mwSecretariatOrAdminFixtures.notSecretariatOrg.short_name) {
      return false
    }

    return true
  }
}

app.route('/only-secretariat-or-admin-pass')
  .post((req, res, next) => {
    const factory = {
      getOrgRepository: () => { return new OrgOnlySecretariatOrAdmin() },
      getUserRepository: () => { return new UserOnlySecretariatOrAdmin() }
    }
    req.ctx.repositories = factory
    next()
  }, middleware.onlySecretariatOrAdmin, (req, res) => {
    return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
  })

describe('Test only Secretariat or Org Admin user middleware', () => {
  context('Positive Tests', function () {
    it('User is a secretariat', function (done) {
      chai.request(app)
        .post('/only-secretariat-or-admin-pass')
        .set(mwSecretariatOrAdminFixtures.secretariatHeaders)
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

    it('User is an admin user', function (done) {
      chai.request(app)
        .post('/only-secretariat-or-admin-pass')
        .set(mwSecretariatOrAdminFixtures.adminHeaders)
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

    it('User is a secretariat and an admin user', function (done) {
      chai.request(app)
        .post('/only-secretariat-or-admin-pass')
        .set(mwSecretariatOrAdminFixtures.secretariatAndAdminHeaders)
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
    it('User is not a secretariat or an admin user', function (done) {
      app.route('/only-secretariat-or-admin-reject')
        .post((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgOnlySecretariatOrAdmin() },
            getUserRepository: () => { return new UserOnlySecretariatOrAdmin() }
          }
          req.ctx.repositories = factory
          next()
        }, middleware.onlySecretariatOrAdmin, (req, res) => {
          return res.status(200).json({ message: 'Success! You have reached the target endpoint.' })
        })

      chai.request(app)
        .post('/only-secretariat-or-admin-reject')
        .set(mwSecretariatOrAdminFixtures.regHeaders)
        .send()
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.notOrgAdminOrSecretariat()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })
  })
})
