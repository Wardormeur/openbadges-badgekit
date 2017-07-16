const validator = require('validator');
const fs = require('fs');
const path = require('path');
const async = require('async');
const url = require('url');
const config = require('../lib/config');
const middleware = require('../middleware');


exports.home = function home (req, res, next) {
  res.render('login/home.html', {
    error: req.flash('error')
  });
};
