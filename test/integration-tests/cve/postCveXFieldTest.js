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
  let cveId, cveIdDollar
  beforeEach(async () => {
    cveId = await helpers.cveIdReserveHelper(requestLength, cveYear, shortName, batchType)
    cveIdDollar = await helpers.cveIdReserveHelper(requestLength, cveYear, shortName, batchType)
  })
  context('Negative Tests', () => {
    it('Should not allow null byte ', async () => {
      // Publish the CVE
      await chai.request(app)
        .post(`/api/cve/${cveId}/cna`)
        .set(constants.nonSecretariatUserHeaders)
        .send({
          cnaContainer: {
            'x_\u0000': true,
            affected: [{
              product: 'p',
              vendor: 'v',
              versions: [
                {
                  version: '1.2',
                  status: 'affected'
                }
              ]
            }],
            descriptions: [{
              lang: 'en',
              value: 'v p 1.2 is insecure.'
            }],
            problemTypes: [{
              descriptions: [{ description: 'insecurity', lang: 'en' }]
            }],
            references: [{ url: 'https://example.com' }]
          }
        })
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(400)
          expect(res.body.message).to.contain('A problem occurred while saving the CVE Record, ensure field names in x_ objects do not start with $ or include a null byte.')
        })
    })
    it('Should not allow $ in start of x_ parameters ', async () => {
      // Publish the CVE
      await chai.request(app)
        .post(`/api/cve/${cveIdDollar}/cna`)
        .set(constants.nonSecretariatUserHeaders)
        .send({
          cnaContainer: {
            $test: true,
            affected: [{
              product: 'p',
              vendor: 'v',
              versions: [
                {
                  version: '1.2',
                  status: 'affected'
                }
              ]
            }],
            descriptions: [{
              lang: 'en',
              value: 'v p 1.2 is insecure.'
            }],
            problemTypes: [{
              descriptions: [{ description: 'insecurity', lang: 'en' }]
            }],
            references: [{ url: 'https://example.com' }]
          }
        })
        .then((res, err) => {
          expect(err).to.be.undefined
          expect(res).to.have.status(400)
          expect(res.body.message).to.contain('CVE cnaContainer JSON schema validation FAILED.')
        })
    })
  })
})
