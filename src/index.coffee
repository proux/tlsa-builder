https = require('https')
crypto = require('crypto')
pem = require('pem')

TlsaBuilder = (_domain, _port = 443, _usage = 3, _selector = 0,
_matchingType = 1, _protocol = 'tcp') ->
  _kv = false
  _record = false

  createResult = (dataField) ->
    if _record
      '_' + _port + '._' + _protocol + '.' + _domain + '.' + ' IN ' +
      _usage + ' ' + _selector + ' ' + _matchingType + ' ' + dataField
    else
      if _kv
        {
          'key': '_' + _port + '._' + _protocol + '.' + _domain + '.'
          'value': _usage + ' ' + _selector + ' ' +
            _matchingType + ' ' + dataField
        }
      else
        _usage + ' ' + _selector + ' ' + _matchingType + ' ' + dataField

  getCertificate = ->
    httpPromise = (resolve, reject) ->
      req = https.request({
        hostname: _domain
        port: _port
      }, (res) ->
        dataField = undefined
        if res.connection.getPeerCertificate().raw instanceof Buffer
          cert = res.connection.getPeerCertificate().raw
          if _selector == 0
            if _matchingType == 1
              dataField = crypto
                .createHash('sha256')
                .update(cert)
                .digest('hex')
            else if _matchingType == 2
              dataField = crypto
                .createHash('sha512')
                .update(cert)
                .digest('hex')
            else
              dataField = cert.toString('hex')
            resolve dataField
          else
            pem.getPublicKey '-----BEGIN CERTIFICATE-----\n' +
              cert.toString('base64') + '\n-----END CERTIFICATE-----',
              (err, result) ->
              if err
                reject new Error(
                  'Could not receive public key from certificate')
              pubKey = new Buffer(result.publicKey
                .replace('-----BEGIN PUBLIC KEY-----\n', '')
                .replace('\n-----END PUBLIC KEY-----', ''), 'base64')
              if _matchingType == 1
                dataField = crypto
                  .createHash('sha256')
                  .update(pubKey)
                  .digest('hex')
              else if _matchingType == 2
                dataField = crypto
                  .createHash('sha512')
                  .update(pubKey)
                  .digest('hex')
              else
                dataField = pubKey.toString('hex')
              resolve dataField
        else
          reject new Error('Could not receive certificate'))
      req.end()
      req.on 'error', (e) ->
        reject new Error('Could not connect to host')

    new Promise(httpPromise)

  builderPromise = (resolve, reject) ->
    if _domain == null || _domain == undefined
      reject new Error('Domain need to be specified')
    else
      getCertificate()
        .then(createResult)
        .then(resolve)
        .catch reject

  @generateKeyValue = ->
    _kv = true
    new Promise(builderPromise)

  @generateValue = ->
    new Promise(builderPromise)

  @generateRecord = ->
    _record = true
    new Promise(builderPromise)

  return

module.exports = TlsaBuilder
