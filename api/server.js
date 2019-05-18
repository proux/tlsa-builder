const TLSARecord = require('../index.js')
const tls = require('tls')

module.exports = (req, res) => {
  let body = ''
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
  if (req.method === 'POST') {
    req.on('data', chunk => { body += chunk.toString() })
    req.on('end', () => {
      body = JSON.parse(body)
      tls.connect(parseInt(body.port), body.domain, function () {
        const tlsaRecord = new TLSARecord(this.getPeerCertificate().raw)
        res.end(JSON.stringify({
          record: tlsaRecord.toString(
            parseInt(body.usage),
            parseInt(body.selector),
            parseInt(body.matchingType),
            body.domain,
            parseInt(body.port),
            body.protocol),
          status: 'ok'
        }))
      })
    })
  } else if (req.method === 'GET') {
    res.writeHead(301, { 'Location': 'https://proux.github.io/tlsa-builder/' })
    res.end()
  } else { res.end() }
}
