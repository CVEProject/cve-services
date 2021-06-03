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

const errors = require('../../../src/controller/org.controller/error')
const error = new errors.OrgControllerError()

const userFixtures = require('./mockObjects.user')
const orgController = require('../../../src/controller/org.controller/org.controller')
const orgParams = require('../../../src/controller/org.controller/org.middleware')

class OrgGetUser {
  async isSecretariat (shortname) {
    return shortname === userFixtures.existentOrg.short_name
  }

  async getOrgUUID (shortname) {
    if (shortname === userFixtures.existentOrg.short_name) {
      return userFixtures.existentOrg.UUID
    } else if (shortname === userFixtures.owningOrg.short_name) {
      return userFixtures.owningOrg.UUID
    }

    return null
  }
}

class UserGetUser {
  async aggregate (aggregation) {
    if (aggregation[0].$match.username === userFixtures.existentUser.username &&
      aggregation[0].$match.org_UUID === userFixtures.existentUser.org_UUID) {
      return [userFixtures.existentUser]
    } else if (aggregation[0].$match.username === userFixtures.existentUserDummy.username &&
      aggregation[0].$match.org_UUID === userFixtures.existentUserDummy.org_UUID) {
      return [userFixtures.existentUserDummy]
    }

    return []
  }
}

describe('Testing the GET /org/:shortname/user/:username endpoint in Org Controller', () => {
  context('Negative Tests', () => {
    it('Org does not exists', (done) => {
      class OrgGetUserOrgDoesntExist {
        async isSecretariat () {
          return true
        }

        async getOrgUUID () {
          return null
        }
      }

      class NullUserRepo {
        async getUserUUID () {
          return null
        }

        async findOneByUserNameAndOrgUUID () {
          return null
        }

        async isAdmin () {
          return null
        }
      }

      app.route('/user-get-user-org-doesnt-exist/:shortname/:username')
        .get((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgGetUserOrgDoesntExist() },
            getUserRepository: () => { return new NullUserRepo() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parseGetParams, orgController.USER_SINGLE)

      chai.request(app)
        .get(`/user-get-user-org-doesnt-exist/${userFixtures.nonExistentOrg.short_name}/${userFixtures.existentUser.username}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(404)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.orgDneParam(userFixtures.nonExistentOrg.short_name)
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })

    it('User does not exists', (done) => {
      class UserGetUserDoesntExist {
        async aggregate () {
          return []
        }
      }

      app.route('/user-get-user-user-doesnt-exist/:shortname/:username')
        .get((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgGetUser() },
            getUserRepository: () => { return new UserGetUserDoesntExist() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parseGetParams, orgController.USER_SINGLE)

      chai.request(app)
        .get(`/user-get-user-user-doesnt-exist/${userFixtures.existentOrg.short_name}/${userFixtures.nonExistentUser.username}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(404)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.userDne(userFixtures.nonExistentUser.username)
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })

    it('User exists and the requester is not secretariat and does not belong to the user\'s org', (done) => {
      app.route('/user-get-user/:shortname/:username')
        .get((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgGetUser() },
            getUserRepository: () => { return new UserGetUser() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parseGetParams, orgController.USER_SINGLE)

      chai.request(app)
        .get(`/user-get-user/${userFixtures.owningOrg.short_name}/${userFixtures.existentUserDummy.username}`)
        .set(userFixtures.orgHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.notSameOrgOrSecretariat()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })
  })

  context('Positive Tests', () => {
    it('User exists and the requester is the secretariat', (done) => {
      app.route('/user-get-user/:shortname/:username')
        .get((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgGetUser() },
            getUserRepository: () => { return new UserGetUser() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parseGetParams, orgController.USER_SINGLE)

      chai.request(app)
        .get(`/user-get-user/${userFixtures.existentOrg.short_name}/${userFixtures.existentUser.username}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('username').and.to.equal(userFixtures.existentUser.username)
          expect(res.body).to.have.property('org_UUID').and.to.equal(userFixtures.existentUser.org_UUID)
          done()
        })
    })

    it('User exists and the requester belongs to the user\'s org', (done) => {
      app.route('/user-get-user/:shortname/:username')
        .get((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgGetUser() },
            getUserRepository: () => { return new UserGetUser() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parseGetParams, orgController.USER_SINGLE)

      chai.request(app)
        .get(`/user-get-user/${userFixtures.owningOrg.short_name}/${userFixtures.existentUserDummy.username}`)
        .set(userFixtures.owningOrgHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('username').and.to.equal(userFixtures.existentUserDummy.username)
          expect(res.body).to.have.property('org_UUID').and.to.equal(userFixtures.existentUserDummy.org_UUID)
          done()
        })
    })
  })
})
