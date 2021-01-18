const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const flash = require('express-flash');
const session =  require('express-session');
const passport = require('passport');

// Requiring database/passport config
const {pool} = require('./dbConfig');
const initializePassport = require('./passportConfig');
initializePassport(passport);

// Declaring PORT
const PORT = 5000 || process.env.PORT;

// Middleware
app.set('view engine', 'ejs');
app.use(flash());
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Data parsing
app.use(express.urlencoded({extended: false}));

// Routing
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/users/register', checkAuthenticated, (req, res) => {
  res.render('register');
});

app.get('/users/login', checkAuthenticated, (req, res) => {
  res.render('login');
});

app.get('/dashboard', checkNotAuthenticated, (req, res) => {
  res.render('dashboard', {user: req.user.name});
});

app.get('/users/logout', (req, res) => {
  res.render('login');
})

// Posting user creation
app.post('/users/register', async (req, res) => {
  let {name, email, password, password2} = req.body;
  console.log({
    name,
    email,
    password,
    password2});
 
  // Form validation
  let errors = [];

  // All fields filled
  if (!name || !email || !password || !password2) {
    errors.push({
      message: 'Please enter all fields.'
    });
  }

  // Password length
  if (password.length < 7) {
    errors.push({
      message: 'Password must be at least 7 characters long.'
    });
  }

  // Check if password and password match
  if (password !== password2) {
    errors.push({
      message: 'Passwords are not matching.'
    });
  }

  // if validation goes wrong
  if (errors.length > 0) {
    res.render('register', {errors});
  } else {
    // Form validation has passsed
    let hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);
    pool.query(
      `SELECT * FROM users
      WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
        }
        console.log(results.rows);
        if (results.rows.length > 0) {
          errors.push({
            message: 'Email already registered.',
          });
          res.render('register', {errors});
        } else {
          pool.query (
            `INSERT INTO users (name, email, password)
              VALUES ($1, $2, $3)
              RETURNING id, password`,
              [name, email, hashedPassword],
              (err, results) => {
                if (err) {
                  throw err;
                }
              console.log(results.rows);
              req.flash('success_msg', 'You are now registered. Please log in.');
              res.redirect('/users/login');
            }
          );
        }
      }
    );
  }
});

// Redirect user after login
app.post('/users/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureFlash: true
  })
);

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/users/dashboard');
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/users/login');
}

// Listening to the PORT
app.listen(PORT, () => {
  console.log(`App listening to the port: ${PORT}.`);
});