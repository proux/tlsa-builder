<form id='form'>
  https://
  <input name='domain' placeholder='domain.com'/>
  <select name='usage'>
      <option value="0">0 - PKIX-TA: Certificate Authority Constraint</option>
      <option value="1">1 - PKIX-EE: Service Certificate Constraint</option>
      <option value="2">2 - DANE-TA: Trust Anchor Assertion</option>
      <option value="3">3 - DANE-EE: Domain Issued Certificate</option>
    </select>
  <select name='selector' >
      <option value="0">0 - Cert: Use full certificate</option>
      <option value="1">1 - SPKI: Use subject public key</option>
    </select>
  <select name='matchingType'>
      <option value="0">0 - Full: No Hash</option>
      <option value="1">1 - SHA-256: SHA-256 hash</option>
      <option value="2">2 - SHA-512: SHA-512 hash</option>
    </select>
    <input name='protocol' value='tcp' placeholder='Protocol' />
    <input name='port' value='443' placeholder='Port'/>
  <input type='submit' />
</form>
<pre id='output'>Input some value and submit</pre>
<script type='text/javascript'>
  document.getElementById('form').addEventListener('submit', function (e) {
    e.preventDefault()
    var formData = new FormData(e.target)
    var object = {}
    formData.forEach(function(value, key){ object[key] = value })
    fetch("https://tlsa.now.sh", { method: "POST", body: JSON.stringify(object) })
      .then(function(res){ return res.json(); })
      .then(function(data){ 
        document.getElementById('output').innerHTML = data.record
      })
  })
</script>