const chai = require('chai')
const expect = chai.expect
const _ = require('lodash')
const cveRecordPublished = require('../../schemas/5.0/CVE-2017-4024_published.json')
const cveRejectExample = require('../../schemas/5.0/rejectCveExample.json')

const Cve = require('../../../src/model/cve')
const cveCopy = _.cloneDeep(cveRecordPublished)

describe('Testing rejecting CVE record that has an ADP container', () => {
  it('Should return rejected Cve record without ADP container', async () => {
    const newRecord = await Cve.updateCveToRejected('', cveRecordPublished.containers.cna.providerMetadata, cveCopy, cveRejectExample)

    expect(newRecord.containers).to.not.have.property('adp')
    expect(cveRecordPublished.containers).to.have.property('adp')
    expect(newRecord.cveMetadata.state).to.equal('REJECTED')
  })
})
