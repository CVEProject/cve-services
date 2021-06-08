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

const CONSTANTS = require('../../../src/constants')
const errors = require('../../../src/controller/org.controller/error')
const error = new errors.OrgControllerError()

const userFixtures = require('./mockObjects.user')
const orgController = require('../../../src/controller/org.controller/org.controller')
const orgParams = require('../../../src/controller/org.controller/org.middleware')

class OrgUserNotUpdatedOrgQueryDoesntExist {
  async getOrgUUID (shortname) {
    if (shortname === userFixtures.existentOrg.short_name) {
      return userFixtures.existentOrg.UUID
    }
    return null
  }

  async isSecretariat () {
    return true
  }
}

class OrgUserUpdatedAddingRole {
  async getOrgUUID () {
    return userFixtures.owningOrg.UUID
  }

  async isSecretariat () {
    return true
  }
}

class UserUpdatedAddingRole {
  constructor () {
    this.user = {
      org_UUID: userFixtures.existentUserDummy.org_UUID,
      username: userFixtures.existentUserDummy.username,
      UUID: userFixtures.existentUserDummy.UUID,
      active: userFixtures.existentUserDummy.active,
      name: userFixtures.existentUserDummy.name,
      authority: {
        active_roles: []
      },
      secret: userFixtures.existentUserDummy.secret
    }

    this.testRes1 = JSON.parse(JSON.stringify(userFixtures.existentUserDummy))
    this.testRes1.authority.active_roles = [CONSTANTS.USER_ROLE_ENUM.ADMIN]
  }

  getUser () {
    this.user.authority.active_roles.push(CONSTANTS.USER_ROLE_ENUM.ADMIN)
    return this.user
  }

  async findOneByUserNameAndOrgUUID () {
    return this.user
  }

  async updateByUserNameAndOrgUUID () {
    return { n: 1, nModified: 1, ok: 1 }
  }

  async getUserUUID () {
    return this.user.UUID
  }

  async isAdmin () {
    return true
  }

  async aggregate () {
    return [this.testRes1]
  }
}

describe('Testing the PUT /org/:shortname/user/:username endpoint in Org Controller', () => {
  context('Negative Tests', () => {
    it('User is not updated because org does not exist', (done) => {
      class OrgUserNotUpdatedOrgDoesntExist {
        async getOrgUUID () {
          return null
        }

        async isSecretariat () {
          return true
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

      app.route('/user-not-updated-org-doesnt-exist/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserNotUpdatedOrgDoesntExist() },
            getUserRepository: () => { return new NullUserRepo() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      const shortname = userFixtures.nonExistentOrg.short_name.replace(/\s/g, '')
      const username = userFixtures.existentUser.username.replace(/\s/g, '')
      chai.request(app)
        .put(`/user-not-updated-org-doesnt-exist/${shortname}/${username}`)
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

    it('User is not updated because user does not exist', (done) => {
      class OrgUserNotUpdatedUserDoesntExist {
        async getOrgUUID () {
          return userFixtures.existentOrg
        }

        async isSecretariat () {
          return true
        }
      }

      class UserNotUpdatedUserDoesntExist {
        async findOneByUserNameAndOrgUUID () {
          return null
        }

        async isAdmin () {
          return null
        }
      }

      app.route('/user-not-updated-doesnt-exist/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserNotUpdatedUserDoesntExist() },
            getUserRepository: () => { return new UserNotUpdatedUserDoesntExist() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      const shortname = userFixtures.existentOrg.short_name.replace(/\s/g, '')
      const username = userFixtures.nonExistentUser.username.replace(/\s/g, '')
      chai.request(app)
        .put(`/user-not-updated-doesnt-exist/${shortname}/${username}`)
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

    it('User is not updated because the new shortname does not exist', (done) => {
      class UserNotUpdatedOrgQueryDoesntExist {
        async findOneByUserNameAndOrgUUID () {
          return userFixtures.existentUser
        }

        async isAdmin () {
          return null
        }
      }

      app.route('/user-not-updated-user-doesnt-exist/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserNotUpdatedOrgQueryDoesntExist() },
            getUserRepository: () => { return new UserNotUpdatedOrgQueryDoesntExist() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      chai.request(app)
        .put(`/user-not-updated-user-doesnt-exist/${userFixtures.existentOrg.short_name}/${userFixtures.existentUser.username}?org_shortname=${userFixtures.nonExistentOrg.short_name}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(404)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.orgDne(userFixtures.nonExistentOrg.short_name)
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })

    it('User is not updated because requestor is not Org Admin, Secretariat, or user', (done) => {
      class Org {
        async getOrgUUID () {
          return userFixtures.existentOrg.UUID
        }

        async isSecretariat () {
          return false
        }
      }

      class User {
        async findOneByUserNameAndOrgUUID () {
          return userFixtures.existentUser
        }

        async isAdmin () {
          return false
        }
      }

      app.route('/user-not-updated-requestor-not-admin-secretariat-user/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new Org() },
            getUserRepository: () => { return new User() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      chai.request(app)
        .put(`/user-not-updated-requestor-not-admin-secretariat-user/${userFixtures.existentOrg.short_name}/${userFixtures.existentUser.username}?org_shortname=${userFixtures.existentOrg.short_name}`)
        .set(userFixtures.owningOrgHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.notSameUserOrSecretariat()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })

    it('User is not updated because requestor is Org Admin of different organization', (done) => {
      class Org {
        async getOrgUUID () {
          return userFixtures.existentOrg.UUID
        }

        async isSecretariat () {
          return false
        }
      }

      class User {
        async findOneByUserNameAndOrgUUID () {
          return userFixtures.existentUser
        }

        async isAdmin (username, shortname) {
          expect(username).to.equal(userFixtures.userDHeader['CVE-API-USER'])
          expect(shortname).to.equal(userFixtures.existentOrgDummy.short_name)
          return true
        }
      }

      app.route('/user-not-updated-requestor-different-admin/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new Org() },
            getUserRepository: () => { return new User() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      chai.request(app)
        .put(`/user-not-updated-requestor-different-admin/${userFixtures.existentOrg.short_name}/${userFixtures.existentUser.username}?org_shortname=${userFixtures.existentOrg.short_name}`)
        .set(userFixtures.userDHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(403)
          expect(res).to.have.property('body').and.to.be.a('object')
          const errObj = error.notSameUserOrSecretariat()
          expect(res.body.error).to.equal(errObj.error)
          expect(res.body.message).to.equal(errObj.message)
          done()
        })
    })

    it('User is not updated because user can\'t update their own active field', (done) => {
      class Org {
        async getOrgUUID () {
          return userFixtures.existentOrgDummy.UUID
        }

        async isSecretariat () {
          return false
        }
      }

      class User {
        async findOneByUserNameAndOrgUUID () {
          return userFixtures.userA
        }

        async isAdmin (username, shortname) {
          expect(username).to.equal(userFixtures.userAHeader['CVE-API-USER'])
          expect(shortname).to.equal(userFixtures.existentOrgDummy.short_name)
          return false
        }
      }

      app.route('/user-not-updated-cant-update-active-field/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new Org() },
            getUserRepository: () => { return new User() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      chai.request(app)
        .put(`/user-not-updated-cant-update-active-field/${userFixtures.existentOrgDummy.short_name}/${userFixtures.userA.username}?active=true`)
        .set(userFixtures.userAHeader)
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

  context('Positive Tests', () => {
    it('User is updated: Adding a user role', (done) => {
      app.route('/user-updated-adding-role-1/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserUpdatedAddingRole() },
            getUserRepository: () => { return new UserUpdatedAddingRole() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      const testUser = Object.assign({}, userFixtures.existentUserDummy)
      testUser.authority = {
        active_roles: [CONSTANTS.USER_ROLE_ENUM.ADMIN]
      }

      chai.request(app)
        .put(`/user-updated-adding-role-1/${userFixtures.owningOrg.short_name}/${testUser.username}?active_roles.add=${CONSTANTS.USER_ROLE_ENUM.ADMIN}&active_roles.add=${CONSTANTS.USER_ROLE_ENUM.ADMIN}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('updated').and.to.be.a('object')
          expect(res.body.updated.authority.active_roles).to.have.lengthOf(1)
          expect(res.body.updated.authority.active_roles[0]).to.equal(testUser.authority.active_roles[0])
          expect(res.body.updated.org_UUID).to.equal(testUser.org_UUID)
          expect(res.body.updated.username).to.equal(testUser.username)
          expect(res.body.updated.UUID).to.equal(testUser.UUID)
          expect(res.body.updated.secret).to.equal(testUser.secret)
          expect(res.body.updated.active).to.equal(testUser.active)
          expect(res.body.updated.name.first).to.equal(testUser.name.first)
          expect(res.body.updated.name.last).to.equal(testUser.name.last)
          expect(res.body.updated.name.middle).to.equal(testUser.name.middle)
          expect(res.body.updated.name.suffix).to.equal(testUser.name.suffix)
          expect(res.body.updated.name.surname).to.equal(testUser.name.surname)
          done()
        })
    })

    it('User is unchanged: Adding a user role that the user already have', (done) => {
      class UserUpdatedAddingRoleAlreadyExists {
        constructor () {
          this.user = {
            org_UUID: userFixtures.existentUserDummy.org_UUID,
            username: userFixtures.existentUserDummy.username,
            UUID: userFixtures.existentUserDummy.UUID,
            active: userFixtures.existentUserDummy.active,
            name: userFixtures.existentUserDummy.name,
            authority: {
              active_roles: [CONSTANTS.USER_ROLE_ENUM.ADMIN]
            },
            secret: userFixtures.existentUserDummy.secret
          }

          this.testRes1 = JSON.parse(JSON.stringify(userFixtures.existentUserDummy))
          this.testRes1.authority.active_roles = [CONSTANTS.USER_ROLE_ENUM.ADMIN]
        }

        getUser () {
          return this.user
        }

        async findOneByUserNameAndOrgUUID () {
          return this.user
        }

        async updateByUserNameAndOrgUUID () {
          return { n: 1, nModified: 1, ok: 1 }
        }

        async getUserUUID () {
          return this.user.UUID
        }

        async isAdmin () {
          return false
        }

        async aggregate () {
          return [this.testRes1]
        }
      }

      app.route('/user-updated-adding-role-2/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserUpdatedAddingRole() },
            getUserRepository: () => { return new UserUpdatedAddingRoleAlreadyExists() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      const testUser = Object.assign({}, userFixtures.existentUserDummy)
      testUser.authority = {
        active_roles: [CONSTANTS.USER_ROLE_ENUM.ADMIN]
      }

      chai.request(app)
        .put(`/user-updated-adding-role-2/${userFixtures.owningOrg.short_name}/${testUser.username}?active_roles.add=${CONSTANTS.USER_ROLE_ENUM.ADMIN}&active_roles.add=${CONSTANTS.USER_ROLE_ENUM.ADMIN}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('updated').and.to.be.a('object')
          expect(res.body.updated.authority.active_roles).to.have.lengthOf(1)
          expect(res.body.updated.authority.active_roles[0]).to.equal(testUser.authority.active_roles[0])
          expect(res.body.updated.org_UUID).to.equal(testUser.org_UUID)
          expect(res.body.updated.username).to.equal(testUser.username)
          expect(res.body.updated.UUID).to.equal(testUser.UUID)
          expect(res.body.updated.secret).to.equal(testUser.secret)
          expect(res.body.updated.active).to.equal(testUser.active)
          expect(res.body.updated.name.first).to.equal(testUser.name.first)
          expect(res.body.updated.name.last).to.equal(testUser.name.last)
          expect(res.body.updated.name.middle).to.equal(testUser.name.middle)
          expect(res.body.updated.name.suffix).to.equal(testUser.name.suffix)
          expect(res.body.updated.name.surname).to.equal(testUser.name.surname)
          done()
        })
    })

    it('User is updated: Removing a user role', (done) => {
      class UserUpdatedRemovingRole {
        constructor () {
          this.user = {
            org_UUID: userFixtures.existentUserDummy.org_UUID,
            username: userFixtures.existentUserDummy.username,
            UUID: userFixtures.existentUserDummy.UUID,
            active: userFixtures.existentUserDummy.active,
            name: userFixtures.existentUserDummy.name,
            authority: {
              active_roles: [CONSTANTS.USER_ROLE_ENUM.ADMIN]
            },
            secret: userFixtures.existentUserDummy.secret
          }

          this.testRes1 = JSON.parse(JSON.stringify(userFixtures.existentUserDummy))
          this.testRes1.authority.active_roles = []
        }

        getUser () {
          this.user.authority.active_roles.splice(0, 1)
          return this.user
        }

        async findOneByUserNameAndOrgUUID () {
          return this.user
        }

        async updateByUserNameAndOrgUUID () {
          return { n: 1, nModified: 1, ok: 1 }
        }

        async getUserUUID () {
          return this.user.UUID
        }

        async isAdmin () {
          return false
        }

        async aggregate () {
          return [this.testRes1]
        }
      }

      app.route('/user-updated-removing-role-1/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserUpdatedAddingRole() },
            getUserRepository: () => { return new UserUpdatedRemovingRole() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      const testUser = Object.assign({}, userFixtures.existentUserDummy)
      testUser.authority = {
        active_roles: [CONSTANTS.USER_ROLE_ENUM.ADMIN]
      }

      chai.request(app)
        .put(`/user-updated-removing-role-1/${userFixtures.owningOrg.short_name}/${testUser.username}?active_roles.remove=${CONSTANTS.USER_ROLE_ENUM.ADMIN}&active_roles.remove=${CONSTANTS.USER_ROLE_ENUM.ADMIN}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('updated').and.to.be.a('object')
          expect(res.body.updated.authority.active_roles).to.have.lengthOf(0)
          expect(res.body.updated.org_UUID).to.equal(testUser.org_UUID)
          expect(res.body.updated.username).to.equal(testUser.username)
          expect(res.body.updated.UUID).to.equal(testUser.UUID)
          expect(res.body.updated.secret).to.equal(testUser.secret)
          expect(res.body.updated.active).to.equal(testUser.active)
          expect(res.body.updated.name.first).to.equal(testUser.name.first)
          expect(res.body.updated.name.last).to.equal(testUser.name.last)
          expect(res.body.updated.name.middle).to.equal(testUser.name.middle)
          expect(res.body.updated.name.suffix).to.equal(testUser.name.suffix)
          expect(res.body.updated.name.surname).to.equal(testUser.name.surname)
          done()
        })
    })

    it('User is unchanged: Removing a user role that the user does not have', (done) => {
      class UserUpdatedRemovingRoleAlreadyRemoved {
        constructor () {
          this.user = {
            org_UUID: userFixtures.existentUserDummy.org_UUID,
            username: userFixtures.existentUserDummy.username,
            UUID: userFixtures.existentUserDummy.UUID,
            active: userFixtures.existentUserDummy.active,
            name: userFixtures.existentUserDummy.name,
            authority: userFixtures.existentUserDummy.authority,
            secret: userFixtures.existentUserDummy.secret
          }
        }

        getUser () {
          return this.user
        }

        async findOneByUserNameAndOrgUUID () {
          return this.user
        }

        async updateByUserNameAndOrgUUID () {
          return { n: 1, nModified: 1, ok: 1 }
        }

        async getUserUUID () {
          return this.user.UUID
        }

        async isAdmin () {
          return false
        }

        async aggregate () {
          return [this.user]
        }
      }

      app.route('/user-updated-removing-role-2/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserUpdatedAddingRole() },
            getUserRepository: () => { return new UserUpdatedRemovingRoleAlreadyRemoved() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      chai.request(app)
        .put(`/user-updated-removing-role-2/${userFixtures.owningOrg.short_name}/${userFixtures.existentUserDummy.username}?active_roles.remove=${CONSTANTS.USER_ROLE_ENUM.ADMIN}&active_roles.remove=${CONSTANTS.USER_ROLE_ENUM.ADMIN}`)
        .set(userFixtures.secretariatHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('updated').and.to.be.a('object')
          expect(res.body.updated.authority.active_roles).to.have.lengthOf(0)
          expect(res.body.updated.org_UUID).to.equal(userFixtures.existentUserDummy.org_UUID)
          expect(res.body.updated.username).to.equal(userFixtures.existentUserDummy.username)
          expect(res.body.updated.UUID).to.equal(userFixtures.existentUserDummy.UUID)
          expect(res.body.updated.secret).to.equal(userFixtures.existentUserDummy.secret)
          expect(res.body.updated.active).to.equal(userFixtures.existentUserDummy.active)
          expect(res.body.updated.name.first).to.equal(userFixtures.existentUserDummy.name.first)
          expect(res.body.updated.name.last).to.equal(userFixtures.existentUserDummy.name.last)
          expect(res.body.updated.name.middle).to.equal(userFixtures.existentUserDummy.name.middle)
          expect(res.body.updated.name.suffix).to.equal(userFixtures.existentUserDummy.name.suffix)
          expect(res.body.updated.name.surname).to.equal(userFixtures.existentUserDummy.name.surname)
          done()
        })
    })

    it('User is updated: Deactivating User as Admin', (done) => {
      class Org {
        async getOrgUUID () {
          return userFixtures.existentOrgDummy.UUID
        }

        async isSecretariat () {
          return false
        }
      }

      class User {
        constructor () {
          this.testRes1 = JSON.parse(JSON.stringify(userFixtures.userA))
          this.testRes1.active = false
        }

        async findOneByUserNameAndOrgUUID () {
          return userFixtures.userA
        }

        async isAdmin (username, shortname) {
          expect(username).to.equal(userFixtures.userDHeader['CVE-API-USER'])
          expect(shortname).to.equal(userFixtures.existentOrgDummy.short_name)
          return true
        }

        async updateByUserNameAndOrgUUID () {
          return { n: 1 }
        }

        async getUserUUID () {
          return userFixtures.userD.UUID
        }

        async aggregate () {
          return [this.testRes1]
        }
      }

      app.route('/user-updated-requestor-admin-deactivate-user/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new Org() },
            getUserRepository: () => { return new User() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      chai.request(app)
        .put(`/user-updated-requestor-admin-deactivate-user/${userFixtures.existentOrgDummy.short_name}/${userFixtures.userA.username}?active=false`)
        .set(userFixtures.userDHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('updated').and.to.be.a('object')
          expect(res.body.updated.active).to.equal(false)
          done()
        })
    })

    it('User is updated: Username changed as user', (done) => {
      class Org {
        async getOrgUUID () {
          return userFixtures.existentOrgDummy.UUID
        }

        async isSecretariat () {
          return false
        }
      }

      class User {
        constructor () {
          this.testRes1 = JSON.parse(JSON.stringify(userFixtures.userA))
          this.testRes1.username = 'TESTER'
        }

        async findOneByUserNameAndOrgUUID () {
          return userFixtures.userA
        }

        async isAdmin (username, shortname) {
          expect(username).to.equal(userFixtures.userAHeader['CVE-API-USER'])
          expect(shortname).to.equal(userFixtures.existentOrgDummy.short_name)
          return false
        }

        async updateByUserNameAndOrgUUID () {
          return { n: 1 }
        }

        async getUserUUID () {
          return userFixtures.userA.UUID
        }

        async find () {
          return []
        }

        async aggregate () {
          return [this.testRes1]
        }
      }

      app.route('/user-updated-requestor-user-username-changed/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new Org() },
            getUserRepository: () => { return new User() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      chai.request(app)
        .put(`/user-updated-requestor-user-username-changed/${userFixtures.existentOrgDummy.short_name}/${userFixtures.userA.username}?new_username=TESTER`)
        .set(userFixtures.userAHeader)
        .end((err, res) => {
          if (err) {
            done(err)
          }

          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('updated').and.to.be.a('object')
          expect(res.body.updated.username).to.equal('TESTER')
          done()
        })
    })

    it('User is unchanged: No query parameters are provided', async () => {
      class UserNotUpdatedNoQuery {
        async findOneByUserNameAndOrgUUID () {
          return userFixtures.existentUser
        }

        async updateByUserNameAndOrgUUID () {
          return { n: 1, nModified: 1, ok: 1 }
        }

        async getUserUUID () {
          return userFixtures.existentUser.UUID
        }

        async isAdmin () {
          return false
        }

        async aggregate () {
          return [userFixtures.existentUser]
        }
      }

      app.route('/user-not-updated-no-parameters/:shortname/:username')
        .put((req, res, next) => {
          const factory = {
            getOrgRepository: () => { return new OrgUserNotUpdatedOrgQueryDoesntExist() },
            getUserRepository: () => { return new UserNotUpdatedNoQuery() }
          }
          req.ctx.repositories = factory
          next()
        }, orgParams.parsePostParams, orgController.USER_UPDATE_SINGLE)

      const res = await chai.request(app)
        .put(`/user-not-updated-no-parameters/${userFixtures.existentOrg.short_name}/${userFixtures.existentUser.username}`)
        .set(userFixtures.secretariatHeader)

      expect(res).to.have.status(200)
      expect(res).to.have.property('body').and.to.be.a('object')
      expect(res.body).to.have.property('updated').and.to.be.a('object')
      expect(res.body.updated.authority.active_roles[0]).to.equal(userFixtures.existentUser.authority.active_roles[0])
      expect(res.body.updated.org_UUID).to.equal(userFixtures.existentUser.org_UUID)
      expect(res.body.updated.username).to.equal(userFixtures.existentUser.username)
      expect(res.body.updated.UUID).to.equal(userFixtures.existentUser.UUID)
      expect(res.body.updated.secret).to.equal(userFixtures.existentUser.secret)
      expect(res.body.updated.active).to.equal(userFixtures.existentUser.active)
      expect(res.body.updated.name.first).to.equal(userFixtures.existentUser.name.first)
      expect(res.body.updated.name.last).to.equal(userFixtures.existentUser.name.last)
      expect(res.body.updated.name.middle).to.equal(userFixtures.existentUser.name.middle)
      expect(res.body.updated.name.suffix).to.equal(userFixtures.existentUser.name.suffix)
      expect(res.body.updated.name.surname).to.equal(userFixtures.existentUser.name.surname)
    })
  })
})
