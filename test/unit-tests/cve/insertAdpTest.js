const chai = require('chai')
const sinon = require('sinon')
const { faker } = require('@faker-js/faker')
const _ = require('lodash')
const expect = chai.expect
const cveIdPublished5 = 'CVE-2017-4024'
const cveRecordPublished = require('../../schemas/5.0/CVE-2017-4024_published.json')
const adpContainer = require('../../schemas/5.0/adpContainerExample.json').adpContainer
const { CVE_INSERT_ADP } = require('../../../src/controller/cve.controller/cve.controller.js')
const errors = require('../../../src/controller/cve.controller/error.js')
const error = new errors.CveControllerError()
const constants = require('../../../src/constants').getConstants()

const OrgRepository = require('../../../src/repositories/orgRepository.js')
const CveIdRepository = require('../../../src/repositories/cveIdRepository.js')
const CveRepository = require('../../../src/repositories/cveRepository.js')
const UserRepository = require('../../../src/repositories/userRepository.js')

const adpUUID = faker.datatype.uuid()

const stubAdpOrg = {
  short_name: 'adpOrg',
  name: 'test_adp',
  UUID: adpUUID,
  authority: {
    active_roles: [
      'ADP'
    ]
  }
}

const stubAdpUser = {
  username: 'testAdpUser',
  org_UUID: adpUUID,
  UUID: faker.datatype.uuid()
}

const stubCveId = {
  requested_by: {
    cna: 'mitre',
    user: 'test_secretariat_0@mitre.org'
  },
  cve_id: 'CVE-2017-4024',
  cve_year: '2017',
  state: 'PUBLISHED',
  owning_cna: 'mitre',
  reserved: '2023-05-17T16:57:35.698Z'
}

describe('Testing insertAdp function', () => {
  let status, json, res, next, getOrgRepository,
    orgRepo, getCveRepository, cveRepo, getCveIdRepository,
    cveIdRepo, getUserRepository, userRepo, adpContainerCopy,
    cveCopy, req

  // Stub out functions called in insertAdp and reset them for each test
  beforeEach(() => {
    status = sinon.stub()
    json = sinon.spy()
    res = { json, status }
    next = sinon.spy()
    status.returns(res)
    orgRepo = new OrgRepository()
    getOrgRepository = sinon.stub()
    getOrgRepository.returns(orgRepo)

    userRepo = new UserRepository()
    getUserRepository = sinon.stub()
    getUserRepository.returns(userRepo)

    cveRepo = new CveRepository()
    getCveRepository = sinon.stub()
    getCveRepository.returns(cveRepo)

    cveIdRepo = new CveIdRepository()
    getCveIdRepository = sinon.stub()
    getCveIdRepository.returns(cveIdRepo)

    // Deep copy because adpContainer and cveRecordPublished are directly modified in inserAdp call
    adpContainerCopy = _.cloneDeep(adpContainer)
    cveCopy = _.cloneDeep(cveRecordPublished)

    sinon.stub(cveIdRepo, 'findOneByCveId').returns(stubCveId)
    sinon.stub(orgRepo, 'getOrgUUID').returns(stubAdpOrg.UUID)
    sinon.stub(userRepo, 'getUserUUID').returns(stubAdpUser.UUID)
    sinon.stub(cveRepo, 'findOneByCveId').returns({ cve: cveCopy })
    sinon.stub(cveRepo, 'updateByCveId').returns(true)

    req = {
      ctx: {
        org: stubAdpOrg.short_name,
        uuid: stubAdpOrg.UUID,
        params: {
          id: cveIdPublished5
        },
        repositories: {
          getOrgRepository,
          getUserRepository,
          getCveRepository,
          getCveIdRepository
        },
        body: {
          adpContainer
        }
      }
    }
  })
  context('Negative Tests', () => {
    it('Should return 400 when ADP json body is the wrong format', async () => {
      req.ctx.body = {
        adpContainerCopy // insertAdp requires the body to have adpContainer property
      }

      await CVE_INSERT_ADP(req, res, next)

      expect(status.args[0][0]).to.equal(400)
      expect(res.json.args[0][0].message).to.equal(error.badAdpFormat().message)
      expect(res.json.args[0][0].error).to.equal(error.badAdpFormat().error)
    })

    it('Should return 400 when ADP fails to validate', async () => {
      adpContainerCopy.affected = {} // affected must be an array per the schema
      req.ctx.body = {
        adpContainer: adpContainerCopy
      }

      await CVE_INSERT_ADP(req, res, next)

      expect(status.args[0][0]).to.equal(400)
      expect(res.json.args[0][0].message).to.equal(error.badAdpJson().message)
      expect(res.json.args[0][0].error).to.equal(error.badAdpJson().error)
    })
  })

  context('Positive Tests', () => {
    it('Should add an ADP container to an existing CVE record', async () => {
      const adpCount = cveCopy.containers.adp.length

      const resMessage = cveIdPublished5 + ' record had new ADP container for org ' + stubAdpOrg.short_name + ' successfully inserted'
      await CVE_INSERT_ADP(req, res, next)

      expect(status.args[0][0]).to.equal(200)
      expect(res.json.args[0][0].message).to.include(resMessage)
      expect(res.json.args[0][0].updated.containers.adp[adpCount].providerMetadata.orgId).to.equal(stubAdpOrg.UUID)
      expect(res.json.args[0][0].updated.containers.adp[adpCount].providerMetadata.shortName).to.equal(stubAdpOrg.short_name)

      // Set providerMetadata on copy, since that field is generated, then compare objects
      adpContainerCopy.providerMetadata = res.json.args[0][0].updated.containers.adp[adpCount].providerMetadata
      expect(res.json.args[0][0].updated.containers.adp[adpCount]).to.deep.equal(adpContainerCopy)
    })

    it('Should update an existing ADP container on an existing CVE record', async () => {
      const adpCopy2 = _.cloneDeep(adpContainer)
      adpCopy2.providerMetadata = {
        orgId: stubAdpOrg.UUID,
        shortName: stubAdpOrg.short_name,
        dateUpdated: faker.date.past()
      }

      // Create adpContainer to modify and add it to record
      cveCopy.containers.adp.push(adpCopy2)

      adpContainerCopy.providerMetadata = {
        orgId: stubAdpOrg.UUID,
        shortName: stubAdpOrg.short_name,
        dateUpdated: faker.date.past()
      }

      // Modify container to test for changes
      adpContainerCopy.affected[0].vendor = 'test'
      req.ctx.body = {
        adpContainer: adpContainerCopy
      }

      const adpCount = cveCopy.containers.adp.length
      const resMessage = cveIdPublished5 + ' record had replacement ADP container for org ' + stubAdpOrg.short_name + ' successfully inserted'
      await CVE_INSERT_ADP(req, res, next)

      expect(status.args[0][0]).to.equal(200)
      expect(res.json.args[0][0].message).to.include(resMessage)
      expect(res.json.args[0][0].updated.containers.adp[adpCount - 1].providerMetadata.orgId).to.equal(stubAdpOrg.UUID)
      expect(res.json.args[0][0].updated.containers.adp[adpCount - 1].providerMetadata.shortName).to.equal(stubAdpOrg.short_name)
      expect(res.json.args[0][0].updated.containers.adp[adpCount - 1].affected[0].vendor).to.equal('test')
      expect(res.json.args[0][0].updated.containers.adp[adpCount - 1]).to.not.deep.equal(adpCopy2)
    })

    it('Should update dataVersion to current version', async () => {
      await CVE_INSERT_ADP(req, res, next)

      expect(status.args[0][0]).to.equal(200)
      expect(res.json.args[0][0].updated.dataVersion).to.equal(constants.SCHEMA_VERSION)
    })
  })
})
