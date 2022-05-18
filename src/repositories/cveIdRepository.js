const BaseRepository = require('./baseRepository')
const CveId = require('../model/cve-id')

class CveIdRepository extends BaseRepository {
  constructor () {
    super(CveId)
  }

  async findOneByCveId (id) {
    return this.collection.findOne().byCveId(id)
  }

  async updateByCveId (id, cveIdObj, options = {}) {
    return this.collection.findOneAndUpdate().byCveId(id).updateOne(cveIdObj).setOptions(options)
  }
}

module.exports = CveIdRepository
