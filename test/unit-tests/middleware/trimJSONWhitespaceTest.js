const chai = require('chai')
const expect = chai.expect
const sinon = require('sinon')

const { trimJSONWhitespace } = require('../../../src/middleware/middleware')

describe('Testing trimJSONWhitespace middleware', () => {
  let status, json, res, next
  beforeEach(() => {
    status = sinon.stub()
    json = sinon.spy()
    res = { json, status }
    next = sinon.spy()
    status.returns(res)
  })

  it('Should successfully trim leading/trailing whitespace for a simple JSON object', async () => {
    const req = {
      body: {
        field1: '     this has whitespace   ',
        field2: 'trailing whitespace only    '
      }
    }
    trimJSONWhitespace(req, res, next)
    expect(req.body).to.be.an('object')
    expect(req.body).to.deep.equal({ field1: 'this has whitespace', field2: 'trailing whitespace only' })
  })

  it('Should successfully trim leading/trailing whitespace for a nested JSON object', async () => {
    const req = {
      body: {
        field1: {
          nestedObj: {
            name: '   Test Name   ',
            secondObj: {
              test: '   second value   '
            }
          }
        }
      }
    }
    trimJSONWhitespace(req, res, next)
    expect(req.body).to.be.an('object')
    expect(req.body).to.deep.equal({
      field1: {
        nestedObj: {
          name: 'Test Name',
          secondObj: {
            test: 'second value'
          }
        }
      }
    })
  })

  it('Should ignore non-string and non-object values', async () => {
    const req = {
      body: {
        test: 'Test Name',
        numberTest: 25
      }
    }
    trimJSONWhitespace(req, res, next)
    expect(req.body).to.be.an('object')
    expect(req.body).to.deep.equal({ test: 'Test Name', numberTest: 25 })
  })
})
