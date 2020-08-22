
async function healthCheck (req, res) {
  res.status(200).send()
}

module.exports = {
  health_check: healthCheck
}
