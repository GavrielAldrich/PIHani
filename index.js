// Import necessary modules
import express from 'express';
import session from 'express-session';
import mysql from 'mysql';
import bcrypt from 'bcrypt';
import passport from 'passport';
import LocalStrategy from 'passport-local';

const app = express();
const port = 3000;

// MySQL connection configuration
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Replace with your MySQL username
    password: '', // Replace with your MySQL password
    database: 'store' // Replace with your database name
});

const saltRounds = 10;

// Configure express-session middleware
app.use(session({
    secret: 'secret', // Change this to a secure random string for production
    resave: false,
    saveUninitialized: false
}));

// Configure passport middleware to use sessions
app.use(passport.initialize());
app.use(passport.session());

// Set the view engine to ejs and specify the views directory
app.set('view engine', 'ejs');
app.set('views', 'views'); // Assuming your views are stored in a directory named 'views'

// Serve static files from the 'public' directory (if you have one)
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Add this line to parse JSON requests

// Set up LocalStrategy for username/password authentication
passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            // Query to find user with the provided username
            const sql = 'SELECT * FROM users WHERE username = ?';
            connection.query(sql, [username], async (err, results) => {
                if (err) {
                    return done(err);
                }

                if (results.length === 0) {
                    return done(null, false, { message: 'User not found' });
                }

                const user = results[0];
                // Compare the provided password with the hashed password from the database
                const passwordMatch = await bcrypt.compare(password, user.password);

                if (passwordMatch) {
                    // Passwords match, return user object
                    return done(null, user);
                } else {
                    // Passwords do not match
                    return done(null, false, { message: 'Incorrect password' });
                }
            });
        } catch (error) {
            return done(error);
        }
    }
));

// Serialize user object to store in session
passport.serializeUser((user, done) => {
    done(null, user.id); // Assuming user.id is unique and can be used to retrieve user from database
});

// Deserialize user object from session
passport.deserializeUser((id, done) => {
    // Query to fetch user by id from database
    const sql = 'SELECT * FROM users WHERE id = ?';
    connection.query(sql, [id], (err, results) => {
        if (err) {
            return done(err);
        }
        if (results.length === 0) {
            return done(new Error('User not found'));
        }
        const user = results[0];
        done(null, user);
    });
});

// Middleware to restrict access to authenticated users only
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/signin'); // Redirect to signin page if not authenticated
};

const ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect('/home'); // Redirect to home page if user is authenticated
    }
    next(); // Continue to the next middleware or route handler
};

const isAdmin = (req, res, next) => {
    // Check if user is authenticated and has role 'admin'
    if (req.isAuthenticated() && req.user.role === 'admin') {
        return next();
    }
    // If not authenticated or not admin, redirect to sign-in page or handle unauthorized access
    res.redirect('/signin'); // Modify as needed
};

// Routes

// Route for rendering index.ejs (accessible to all)
app.get('/', isAuthenticated, (req, res) => {
    res.render('index');
});

// Route for rendering home.ejs (restricted to authenticated users)
app.get('/home', isAuthenticated, (req, res) => {
    res.render('home');
});

// Route for rendering albums.ejs (restricted to authenticated users)
app.get('/albums', isAuthenticated, (req, res) => {
    res.render('albums');
});

// Route for rendering officialmerchandise.ejs (restricted to authenticated users)
app.get('/officialmerchandise', isAuthenticated, (req, res) => {
    res.render('officialmerchandise');
});

// Route for rendering lightsticks.ejs (restricted to authenticated users)
app.get('/lightsticks', isAuthenticated, (req, res) => {
    res.render('lightsticks');
});

// Route for rendering signin.ejs
app.get('/signin', ensureAuthenticated, (req, res) => {
    res.render('signin');
});

// Route for rendering admin page (restricted to authenticated admins)
app.get('/adminpage', isAuthenticated, isAdmin, (req, res) => {
    const query = 'SELECT * FROM products';
    connection.query(query, (err, products) => {
        if (err) {
            console.error('Error retrieving products:', err);
            res.status(500).send('Error retrieving products');
            return;
        }
        res.render('adminpage', { products }); // Render adminpage and pass products data
    });
});

// Route for rendering add product form (restricted to authenticated admins)
app.get('/adminpage/addproduct', isAuthenticated, isAdmin, (req, res) => {
    res.render('addproduct');
});

// Route for handling form submission to add product
app.post('/adminpage/addproduct', isAuthenticated, isAdmin, (req, res) => {
    const { judul, deskripsi, harga } = req.body;

    // Insert product into the database
    const query = 'INSERT INTO products (product_name, product_desc, product_price) VALUES (?, ?, ?)';
    connection.query(query, [judul, deskripsi, harga], (err, result) => {
        if (err) {
            console.error('Error inserting product:', err);
            res.status(500).send('Error adding product');
            return;
        }
        console.log('Product added successfully');
        res.redirect('/adminpage/addproduct'); // Redirect to admin page after adding product
    });
});

// POST route for handling signin form submission
app.post('/signin', ensureAuthenticated, passport.authenticate('local', {
    successRedirect: '/home', // Redirect to home page on successful login
    failureRedirect: '/signin', // Redirect back to signin page on failure
}));

// POST route for handling signup form submission
app.post('/signup', ensureAuthenticated, async (req, res) => {
    const { email, no_telp, username, gender, fullname, address, password } = req.body;
    const lowerCasedEmail = email.toLowerCase();
    const lowerCasedUsername = username.toLowerCase();
    const role = 'user';
    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Store username, hashedPassword, and other details in your database
        const sql = 'INSERT INTO users (email, no_telp, username, gender, fullname, address, password, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        connection.query(sql, [lowerCasedEmail, no_telp, lowerCasedUsername, gender, fullname, address, hashedPassword, role], (err, result) => {
            if (err) {
                console.error(err);
                res.status(500).send('Error saving user');
                return;
            }
            console.log('User registered successfully');
            res.redirect('/signin'); // Redirect to signin page after successful registration
        });
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// Route for rendering signup.ejs
app.get('/signup', ensureAuthenticated, (req, res) => {
    res.render('signup');
});

// POST route for handling logout
app.post('/logout', (req, res) => {
    req.logout(err => {
        if (err) {
            console.error(err);
            return res.status(500).send('Logout failed');
        }
        res.redirect('/signin'); // Redirect to signin page after logout
    });
});

// Start server
app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
