const OrgRepository = require('./orgRepository')
const CveRepository = require('./cveRepository')
const CveIdRepository = require('./cveIdRepository')
const CveIdRangeRepository = require('./cveIdRangeRepository')
const UserRepository = require('./userRepository')

class RepositoryFactory {
  getOrgRepository () {
    const repo = new OrgRepository()
    return repo
  }

  getCveRepository () {
    const repo = new CveRepository()
    return repo
  }

  getCveIdRepository () {
    const repo = new CveIdRepository()
    return repo
  }

  getCveIdRangeRepository () {
    const repo = new CveIdRangeRepository()
    return repo
  }

  getUserRepository () {
    const repo = new UserRepository()
    return repo
  }
}

module.exports = RepositoryFactory
