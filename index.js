'use strict'

const rfc = require('asn1.js-rfc5280')
const crypto = require('crypto')

class TLSARecord {
  constructor (certificate) {
    if (!Buffer.isBuffer(certificate)) {
      certificate = Buffer.from(certificate
        .replace(/\n/g, '')
        .replace(/\r/g, '')
        .replace('-----BEGIN CERTIFICATE-----', '')
        .replace('-----END CERTIFICATE-----', '')
        .replace(/ /g, ''), 'base64')
    }
    const asn1 = rfc.Certificate.decode(certificate, 'der')
    this.publicKey = rfc.SubjectPublicKeyInfo.encode(asn1.tbsCertificate.subjectPublicKeyInfo, 'der')
    this.certificate = certificate
  }

  selectData (selector) {
    if (selector < 0 || selector > 1) {
      throw new Error('')
    }
    return selector === 1 ? this.publicKey : this.certificate
  }

  createData (dataField, matchingType) {
    switch (matchingType) {
      case 0: {
        return dataField.toString('hex')
      }
      case 1: {
        return crypto
          .createHash('sha256')
          .update(dataField)
          .digest('hex')
      }
      case 2: {
        return crypto
          .createHash('sha512')
          .update(dataField)
          .digest('hex')
      }
      default: {
        throw new Error('')
      }
    }
  }

  toString (usage, selector, matchingType, domain, port = 443, protocol = 'tcp') {
    const data = this.toObject(usage, selector, matchingType, domain, port, protocol)
    return data.name + ' IN TLSA ' + data.data
  }

  toObject (usage, selector, matchingType, domain, port = 443, protocol = 'tcp') {
    return {
      name: '_' + port + '._' + protocol + '.' + domain + '.',
      type: 'TLSA',
      data: usage + ' ' + selector + ' ' + matchingType + ' ' +
        this.createData(this.selectData(selector), matchingType)
    }
  }
}

module.exports = TLSARecord
