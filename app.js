//jshint esversion:6

require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');



const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true });
mongoose.set('strictQuery', true);
app.get("/", function (req, res) {
    res.render("home");
});



//Setting user schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: [String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secretly.up.railway.app/auth/google/secretly",
    // callbackURL: "http://localhost:3000/auth/google/secretly",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    passReqToCallback: true
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ username: profile.emails[0].value, googleId: profile.id, age: profile.age }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/login", function (req, res) {
    res.render("login");
});


app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/secretly", passport.authenticate("google", { failureRedirect: "/login", successRedirect: "/secrets" })
);

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    User.find({ "secret": { $ne: null } }, (err, foundUsers) => {
        if (err) {
            console.log(err);
        }
        else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    })
});

app.get("/submit", (req, res) => {
    if (passport.authenticate("google") || passport.authenticate("local")) {
        console.log("authenticated");
        res.render("submit");
    }
    else {
        console.log("not authenticated");
        res.redirect("/login");
    }
})

app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
        }
        else {
            res.redirect("/");
        }
    });
});

app.post("/register", (req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        }
        else {
            passport.authenticate("local", "google")(req, res, () => {
                res.redirect("/secrets");
            })
        }
    })
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    // console.log("user id: " + req.user.id);
    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
        }
        else {
            if (foundUser) {
                foundUser.secret.push(submittedSecret);

                foundUser.save(() => {
                    res.redirect("/secrets");
                })
            }
        }
    })
})



app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, (err) => {
        if (err) {
            console.log(err);
        }
        else {
            console.log("id: " + req.user.id);
            passport.authenticate("local");
            console.log("authenticated");
            res.redirect("/secrets");
        }
    })

});

app.listen(3000 || process.env.PORT, function () {
    console.log("Server started on port 3000");
}); 