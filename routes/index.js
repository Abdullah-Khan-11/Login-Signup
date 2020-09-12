var express = require('express');
var userModel = require('../module/user');
var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
var router = express.Router();

/* GET home page. */

function CheckLogin (req, res, next) {
  var userToken = localStorage.getItem('userToken');
  try {
      var decoded = jwt.verify(userToken, 'loginToken');
  } catch (err) {
    res.redirect('/');
  }
  next ();
}

if (typeof localStorage === "undefined" || localStorage === null) {
  var LocalStorage = require('node-localstorage').LocalStorage;
  localStorage = new LocalStorage('./scratch');
}

function checkUsername (req, res, next) {
  var username = req.body.uname;
  var checkexitUsername = userModel.findOne ({ username : username});
  checkexitUsername.exec((err, data)=>{
    if (err) throw err;
    if (data) {
      res.render('signup', { title : "Malak Khan", msg : "Username are taken"});
    }
  });
  next (); 
}

function checkEmail (req, res, next) {
  var email = req.body.email;
  var checkexitEmail = userModel.findOne({ email : email });
  checkexitEmail.exec((err, data)=>{
    if (err) throw err;
    if (data) {
      res.render('signup', { title : "Malak Khan", msg : "Email are taken"});
    }
  });
  next ();
}

router.get('/', function (req, res, next){
  res.render('index', { title : "Malak Khan", msg : ''})
});

router.post('/', function (req, res, next){
  var username = req.body.uname;
  var password = req.body.password;
  var checkLoginUser = userModel.findOne({ username : username});
  checkLoginUser.exec((err, data)=>{
    if (err) throw err;

    var getUserID = data._id;
    var getPassword = data.password;
    if (bcrypt.compareSync(password, getPassword)){
      var token = jwt.sign({ userID : getUserID}, 'loginToken');
      localStorage.setItem('userToken', token);
      localStorage.setItem('loginUser', username);
      res.redirect('./dashboard');
    }else {
      res.render('index', { title : "Malak Khan", msg : "CheckUsername & Password "})
    }
  });
});

router.get('/signup', function (req, res, next){
   res.render('signup', { title : "Malak Khan", msg : ''});
});   

router.post('/signup', checkUsername, checkEmail, function (req, res, next){
  var username = req.body.uname;
  var email = req.body.email;
  var password = req.body.password;
  var confpassword = req.body.confpassword;

  if (password != confpassword){
    res.render('signup', { title : "Malak Khan", msg : "Password Doesn't Match"});
  }
  password = bcrypt.hashSync(req.body.password, 10);
  var userDetails = new userModel ({
    username : username,
    email : email,
    password : password
  });
  userDetails.save((err, doc)=>{
    if (err) throw err;
    res.render('signup', { title : "Malak Khan", msg : "Inserted Successfully"});
  });
});

router.get('/dashboard', CheckLogin, function (req, res, next){
 var loginUser = localStorage.getItem ('loginUser');
 res.render('dashboard', { title : "Malak Khan", loginUser : loginUser});
});

router.get('/logout', function (req, res, next){
  localStorage.removeItem('loginUser');
  localStorage.removeItem('loginToken');
  res.redirect('/');
});

module.exports = router;
