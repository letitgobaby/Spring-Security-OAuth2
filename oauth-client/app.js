var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var login = require('./routes/login');
var auth = require('./routes/auth');

var app = express();
var port = 7777;

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.engine('html', require('ejs').renderFile);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use('/', login);
app.use('/', auth);

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
