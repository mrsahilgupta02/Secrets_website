//jshint esversion:6
require('dotenv').config();//used  to keep secrets safe
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
//const encrypt =require("mongoose-encryption");
const app = express();

//these below packages are for authentication
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");//this package automatically hash and salt the password
//hashing func   const md5 = require("md5");
// const bcrypt = require("bcrypt");
// const saltRounds = 10;              // how many salt rounds you want to do
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const findOrCreate = require('mongoose-findorcreate');
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));


app.use(session({                //this palce must be right above mongoose.connect
  secret: "Our little Secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

//console.log();
const userSchema = new mongoose.Schema( {
  email: String,
  password:String,
  googleId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
    //we can say that now secret is our encryption key
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password'] });//plugins work is to add new functionality to our schema
//                                                                            //here we encrypt password

const User = new mongoose.model("User",userSchema);

passport.use(User.createStrategy());    //these three lines of code must be always right below mongoose.model

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {

    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets",function(req,res){
  User.find({"secret": {$ne: null}},function(err,foundUsers){
    if(err){
      console.log(err);
    }
    else{
      if(foundUsers){
        res.render("secrets",{usersWithSecrets: foundUsers});
      }
    }
  })  ;//this will find the data where data is not null
});

app.get("/submit",function(req,res){
  if (req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});


app.get("/logout",function(req, res){
  req.logout(function(err){
    if(err)
    {
      console.log(err);
    }
    else{
      res.redirect("/");
    }
  });

});

app.post("/submit",function(req,res){
  const submittedSecret = req.body.secret;
User.findById(req.user.id, function(err, foundUser){
  if(err){
    console.log(err);
  }
  else{
    if(foundUser){
      foundUser.secret =submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  }
});
//  console.log(req.user);
});


app.post("/register",function(req,res){
    User.register({username: req.body.username},req.body.password,function(err,user){
      if(err){
        console.log(err);
      }
      else{
        passport.authenticate("local")(req ,res , function(){
          res.redirect("/");
        });
      }
    });




 //  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
 //    const newUser = new User({
 //      email:req.body.username,
 //      password: hash
 //    });
 //    newUser.save(function(err){
 //      if(err){
 //        console.log(err);
 //      }
 //      else
 //      {
 //        res.render("secrets");
 //      }
 //    });
 //
 // });

});

//md5 hash your password

app.post("/login",function(req,res){

    const user = new User({
      username: req.body.username,
      password: req.body.password
    });

     req.login(user ,function(err){          //.login is passport's method
       if(err){
         console.log(err);
       }
       else{
         passport.authenticate("local")(req ,res , function(){
           res.redirect("/secrets");
         });
       }
     });




  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email:username},function(err,foundUser){
  //   if(err){                                            //we will find a user of given email
  //     console.log(err);                                 //if err console it
  //   }
  //   else{
  //     if(foundUser){                                    //if user is found of that email check its password
  //       bcrypt.compare(password, foundUser.password, function(err, result) { // here we compare the encypted version of what we entered and the password which was encrypted at time of register
  //            if(result === true){
  //              res.render("secrets");
  //            }
  //    });
  //     }
  //   }
  // });
});

app.listen(3000, function() {
  console.log("Server started on port 3000");
});
