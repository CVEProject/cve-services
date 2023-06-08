/* eslint-disable no-unused-expressions */

const chai = require('chai')
chai.use(require('chai-http'))

const expect = chai.expect

const constants = require('../constants.js')
const app = require('../../../src/index.js')

const helpers = require('../helpers.js')

const requestLength = 1
const shortName = 'win_5'
const cveYear = '2023'
const batchType = 'non-sequential'

describe('Testing Reserve CVE Endpoint', () => {
  let cveId
  beforeEach(async () => {
    cveId = await helpers.cveIdReserveHelper(requestLength, cveYear, shortName, batchType)
  })
  context('Positive Tests', () => {
    it('Testing Reservation of CVE ', async () => {
      // Publish the CVE
      await chai.request(app)
        .post(`/api/cve/${cveId}/cna`)
        .set(constants.nonSecretariatUserHeaders)
        .send(constants.testCve)
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(200)
          expect(res).to.have.property('body').and.to.be.a('object')
          expect(res.body).to.have.property('created').and.to.be.a('object')
          expect(res.body.created).to.have.nested.property('cveMetadata.cveId')
          expect(res.body.created).to.have.nested.property('cveMetadata.state')
        })
    })
  })
})
