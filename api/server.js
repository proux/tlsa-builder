const TLSARecord = require('../index.js')
const https = require('https')

module.exports = (req, res) => {
  let body = ''
  res.setHeader('Content-Type', 'application/json')
  if (req.method === 'POST') {
    req.on('data', chunk => { body += chunk.toString() })
    req.on('end', () => {
        body = JSON.parse(body)
        https.get('https://' + body.domain, (resp) => {
            const tlsaRecord = new TLSARecord(resp.connection.getPeerCertificate().raw)
            const result = {  
                record: tlsaRecord.toString(
                    parseInt(body.usage),
                    parseInt(body.selector),
                    parseInt(body.matchingType),
                    body.domain,
                    parseInt(body.port),
                    body.protocol),
                status: 'ok'
            }
            res.end(JSON.stringify(result))
        }).on("error", err => res.end('{"status":"error"}'))
    })
  } else { res.end('{}') }
}
