var express = require('express');
var router = express.Router();



/* GET home page. */
router.get('/auth', function(req, res, next) {
  var response_type = 'code';
  var client_id = 'test';
  var redirect_uri = 'http://localhost:7777/auth';

  console.log('query', res.query);
  console.log('body', res.body);

  if (req.query.code) {
    var grant_type = 'authorization_code';
    var client_secret = 'test';
    res.redirect(`http://localhost:8081/sub/token?grant_type=${grant_type}&client_id=${client_id}&client_secret=${client_secret}&redirect_uri=${redirect_uri}&code=${req.query.code}`);
  } else {
    res.redirect(`http://localhost:8081/sub/authorize?response_type=${response_type}&client_id=${client_id}&redirect_uri=${redirect_uri}`);
  }
  
});

module.exports = router;