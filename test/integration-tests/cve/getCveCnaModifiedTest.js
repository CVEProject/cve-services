/* eslint-disable no-unused-expressions */

const chai = require('chai')
chai.use(require('chai-http'))
const expect = chai.expect

const constants = require('../constants.js')
const app = require('../../../src/index.js')
const helpers = require('../helpers.js')
const _ = require('lodash')

const shortName = 'win_5'

describe('Test cna_modified parameter for get CVE', () => {
  let cveId
  before(async () => {
    cveId = await helpers.cveIdReserveHelper(1, '2023', shortName, 'non-sequential')
    await helpers.cveRequestAsCnaHelper(cveId)
  })
  context('Positive Test', () => {
    it('Get CVE with cna_modified set to true AND date.gt should return when searched with a known earlier than date', async () => {
      await chai.request(app)
        .get('/api/cve/?time_modified.gt=2022-01-01T00:00:00&cna_modified=true')
        .set(constants.headers)
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(200)
          expect(_.some(res.body.cveRecords, { cveMetadata: { cveId: cveId } })).to.be.true
        })
    })
    it('Get CVE with cna_modified set to true AND date.gt should return and empty list when searched with a known bad earlier than date', async () => {
      await chai.request(app)
        .get('/api/cve/?time_modified.gt=2100-01-01T00:00:00&cna_modified=true')
        .set(constants.headers)
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(200)
          expect(_.some(res.body.cveRecords, { cveMetadata: { cveId: cveId } })).to.be.false
        })
    })

    it('Get CVE with cna_modified set to true AND date.lt should return when searched with a known later than date', async () => {
      await chai.request(app)
        .get('/api/cve/?time_modified.lt=2100-01-01T00:00:00&cna_modified=true')
        .set(constants.headers)
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(200)
          expect(_.some(res.body.cveRecords, { cveMetadata: { cveId: cveId } })).to.be.true
        })
    })
    it('Get CVE with cna_modified set to true AND date.lt should return and empty list when searched with a known bad later than date', async () => {
      await chai.request(app)
        .get('/api/cve/?time_modified.lt=2022-01-01T00:00:00&cna_modified=true')
        .set(constants.headers)
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(200)
          expect(_.some(res.body.cveRecords, { cveMetadata: { cveId: cveId } })).to.be.false
        })
    })
  })
  context('Negative Tests', () => {
    it('CVE should NOT be returned with cna_modified true as it has been created', async () => {
      await chai.request(app)
        .get('/api/cve/?cna_modified=true')
        .set(constants.headers)
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(400)
        })
    })
    it('Get CVE with cna_modified set to true should NOT be returned after being edited', async () => {
      // Edit the CNA container
      await helpers.cveUpdatetAsCnaHelperWithCnaContainer(cveId, constants.testCveEdited)
      await chai.request(app)
        .get('/api/cve/?cna_modified=true')
        .set(constants.headers)
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(400)
        })
    })
  })
})
