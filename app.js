/////// app.js

const path = require('node:path');
const pool = require('./db/pool');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: 'Incorrect username' });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        // passwords do not match!
        return done(null, false, { message: 'Incorrect password' });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});

const app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(session({ secret: 'cats', resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

let admin = false;

app.get('/', async (req, res) => {
  const result = await pool.query('SELECT * FROM data_storage ORDER BY id');
  const messages = result.rows.map((row) => ({
    id: row.id,
    message: row.data,
    author: row.auther,
  }));
  res.render('index', { isadmin: admin, user: req.user, messages: messages });
});

app.get('/sign-up', (req, res) => res.render('sign-up-form'));

app.post('/sign-up', async (req, res, next) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [
      req.body.username,
      hashedPassword,
    ]);
    res.redirect('/');
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.post(
  '/log-in',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/',
  })
);

app.get('/log-out', (req, res, next) => {
  admin = false;
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

app.get('/create_post', async (req, res, next) => {
  res.render('createpost', { user: req.user });
});

app.post('/create_post', async (req, res, next) => {
  const { input, author } = req.body;
  try {
    await pool.query('INSERT INTO data_storage (data, auther) VALUES($1,$2)', [
      input,
      author,
    ]);
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Server error');
  }
});

app.post('/admin', async (req, res, next) => {
  const { adminpw } = req.body;
  admin = false; // default
  if (adminpw === 'lovecode') {
    admin = true;
  }
  if (admin) {
    res.redirect('/');
  } else {
    res.send(`
    <h1>Access Denied!</h1>
    <p>Redirecting back...</p>
    <script>
      setTimeout(() => {
        window.location.href = '/';
      }, 2000);
    </script>
  `);
  }
});

app.get('/delete/:index', async (req, res) => {
  const id = parseInt(req.params.index);
  try {
    await pool.query('DELETE FROM data_storage WHERE id=$1', [id]);
    res.redirect('/');
  } catch (err) {
    console.error('Error deleting game:', err);
    res.status(500).send('Server Error');
  }
});

app.listen(3000, (error) => {
  if (error) {
    throw error;
  }
  console.log('app listening on port 3000!');
});
