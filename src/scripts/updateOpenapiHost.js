const replaceInFile = require('replace-in-file')

if (process.env.NODE_ENV === 'development') {
  replaceInFile.sync({
    files: 'api-docs/openapi.json',
    from: 'urlplaceholder',
    to: 'https://cveawg-dev.mitre.org/api'
  })
}

if (process.env.NODE_ENV === 'staging') {
  replaceInFile.sync({
    files: 'api-docs/openapi.json',
    from: 'urlplaceholder',
    to: 'https://cveawg-test.mitre.org/api'
  })
}

if (process.env.NODE_ENV === 'integration') {
  replaceInFile.sync({
    files: 'api-docs/openapi.json',
    from: 'urlplaceholder',
    to: 'https://cveawg-int.mitre.org/api'
  })
}

if (process.env.NODE_ENV === 'production') {
  replaceInFile.sync({
    files: 'api-docs/openapi.json',
    from: 'urlplaceholder',
    to: 'https://cveawg.mitre.org/api'
  })
}
