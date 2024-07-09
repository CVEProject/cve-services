/* eslint-disable no-unused-expressions */

const chai = require('chai')
const expect = chai.expect
const _ = require('lodash')

const { datePublicHelper } = require('../../../src/controller/cve.controller/cve.middleware')
const tempValidDatePublicRecord = require('../../schemas/5.0/CVE-2017-4024_published.json')
const validDatePublicRecord = _.cloneDeep(tempValidDatePublicRecord)
const inValidDatePublicRecord = require('../../schemas/5.0/CVE-2017-4024_published_bad_datePublic.json')

describe('Testing validateDatePublic middleware', () => {
  context('Negative Tests', () => {
    it('Should throw an error for datePublic dates in the future ', () => {
      const result = datePublicHelper(inValidDatePublicRecord.containers.cna.datePublic)
      expect(result).to.be.false
    })
  })

  context('Positive Tests', () => {
    it('Should return true for records with datePublic in the past', () => {
      const result = datePublicHelper(validDatePublicRecord.containers.cna.datePublic)
      expect(result).to.be.true
    })
    it('Should return true for records with datePublic within 24 hours of currentDate', () => {
      let datePublic = new Date()
      datePublic.setDate(datePublic.getDate() - 1)
      datePublic = datePublic.toISOString()
      const result = datePublicHelper(datePublic)
      expect(result).to.be.true
    })
  })
})
