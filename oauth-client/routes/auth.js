const express = require('express');
const axios = require('axios');
const router = express.Router();

var response_type = 'code';
var grant_type = 'authorization_code';
var client_id = 'abc'; // 사이트에서 발급 후 고정 사용
var client_secret = 'abc'; // 사이트에서 발급 후 고정 사용
var redirect_uri = 'http://localhost:7777/auth/a';

var store = null;

router.get('/main', (req, res, next) => {
  res.render('main.html', { 'token' : store });
});

router.get('/auth/a', (req, res, next) => {
  if (req.query.error) {
    res.redirect('/login');
  } else if (req.query.code) {
    axios.post('http://localhost:8081/sub/token', {
      grant_type, client_id, client_secret, redirect_uri,
      code: req.query.code
    })
    .then(response => {
      console.log('Token Receive !!', response.data.data );
      store = response.data.data;
      res.redirect('/main');
    })
    .catch(err => console.log('ERROR ', err));

  } else {
    res.redirect(`http://localhost:8081/sub/authorize?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}`);
  }
});

router.get('/info', async (req, res, next) => {
  var result = await axios.get('http://localhost:8081/user/info', {
      headers: { Authorization: `Bearer ${store.accessToken}` }
    });

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.write(JSON.stringify(result.data));
  res.end();
})

module.exports = router;