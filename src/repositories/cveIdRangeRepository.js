const BaseRepository = require('./baseRepository')
const CveIdRange = require('../model/cve-id-range')

class CveIdRangeRepository extends BaseRepository {
  constructor () {
    super(CveIdRange)
  }
}

module.exports = CveIdRangeRepository
