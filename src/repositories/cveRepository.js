const BaseRepository = require('./baseRepository')
const Cve = require('../model/cve')

class CveRepository extends BaseRepository {
  constructor () {
    super(Cve)
  }

  async findOneByCveId (id) {
    const results = this.collection.findOne().byCveId(id)
    return results
  }

  async updateByCveId (id, cve, options = {}) {
    return this.collection.findOneAndUpdate().byCveId(id).updateOne(cve).setOptions(options)
  }
}

module.exports = CveRepository
