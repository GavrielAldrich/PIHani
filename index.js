// Import necessary modules
import express from "express";
import session from "express-session";
import mysql from "mysql";
import bcrypt from "bcrypt";
import passport from "passport";
import LocalStrategy from "passport-local";
import multer from "multer";

const app = express();
const port = 3000;

// MySQL connection configuration
const connection = mysql.createConnection({
  host: "localhost",
  user: "root", // Replace with your MySQL username
  password: "", // Replace with your MySQL password
  database: "store", // Replace with your database name
});

const saltRounds = 10;

// Configure express-session middleware
app.use(
  session({
    secret: "secret", // Change this to a secure random string for production
    resave: false,
    saveUninitialized: false,
  })
);

// Multer configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads"); // Directory where files will be stored
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9); // Generate unique suffix
    const originalname = file.originalname.toLowerCase().split(" ").join("-"); // Change spaces in name to hyphens
    cb(null, uniqueSuffix + "-" + originalname); // Use the unique suffix and original filename
  },
});

const upload = multer({ storage: storage });

// Configure passport middleware to use sessions
app.use(passport.initialize());
app.use(passport.session());

// Set the view engine to ejs and specify the views directory
app.set("view engine", "ejs");
app.set("views", "views"); // Assuming your views are stored in a directory named 'views'

// Serve static files from the 'public' directory (if you have one)
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Add this line to parse JSON requests

// Set up LocalStrategy for username/password authentication
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      // Query to find user with the provided username
      const sql = "SELECT * FROM users WHERE username = ?";
      connection.query(sql, [username], async (err, results) => {
        if (err) {
          return done(err);
        }

        if (results.length === 0) {
          return done(null, false, { message: "User not found" });
        }

        const user = results[0];
        // Compare the provided password with the hashed password from the database
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (passwordMatch) {
          // Passwords match, return user object
          return done(null, user);
        } else {
          // Passwords do not match
          return done(null, false, { message: "Incorrect password" });
        }
      });
    } catch (error) {
      return done(error);
    }
  })
);

// Serialize user object to store in session
passport.serializeUser((user, done) => {
  done(null, user.id); // Assuming user.id is unique and can be used to retrieve user from database
});

// Deserialize user object from session
passport.deserializeUser((id, done) => {
  // Query to fetch user by id from database
  const sql = "SELECT * FROM users WHERE id = ?";
  connection.query(sql, [id], (err, results) => {
    if (err) {
      return done(err);
    }
    if (results.length === 0) {
      return done(new Error("User not found"));
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
  res.redirect("/signin"); // Redirect to signin page if not authenticated
};

const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return res.redirect("/home"); // Redirect to home page if user is authenticated
  }
  next(); // Continue to the next middleware or route handler
};

const isAdmin = (req, res, next) => {
  // Check if user is authenticated and has role 'admin'
  if (req.isAuthenticated() && req.user.role === "admin") {
    return next();
  }
  // If not authenticated or not admin, redirect to sign-in page or handle unauthorized access
  res.send("You are not an admin"); // Modify as needed
};

// Routes

// Route for rendering index.ejs (accessible to all)
app.get("/", isAuthenticated, (req, res) => {
  res.render("index");
});

// Route for rendering home.ejs (restricted to authenticated users)
app.get("/home", isAuthenticated, (req, res) => {
  res.render("home");
});

// Route for rendering albums.ejs (restricted to authenticated users)
app.get("/albums", isAuthenticated, (req, res) => {
  const query = "SELECT * FROM products WHERE product_type = 'albums'";
  connection.query(query, (err, albums) => {
    if (err) {
      console.error("Error retrieving albums:", err);
      res.status(500).send("Error retrieving albums");
      return;
    }
    res.render("albums", { products: albums });
  });
});

// Route to render OfficialMerchandise page with all products
app.get("/officialmerchandise", (req, res) => {
  const query =
    'SELECT * FROM products WHERE product_type IN ("albums", "lightsticks")'; // Fetch products from albums and lightsticks categories
  connection.query(query, (err, products) => {
    if (err) {
      console.error("Error retrieving products:", err);
      res.status(500).send("Error retrieving products");
      return;
    }
    res.render("OfficialMerchandise", { products }); // Render OfficialMerchandise.ejs and pass products data
  });
});

// Route for rendering lightsticks.ejs (restricted to authenticated users)
app.get("/lightsticks", isAuthenticated, (req, res) => {
  const query = "SELECT * FROM products WHERE product_type = 'lightsticks'";
  connection.query(query, (err, lightsticks) => {
    if (err) {
      console.error("Error retrieving lightsticks:", err);
      res.status(500).send("Error retrieving lightsticks");
      return;
    }
    res.render("lightsticks", { products: lightsticks });
  });
});

// Route for rendering signin.ejs
app.get("/signin", ensureAuthenticated, (req, res) => {
  res.render("signin");
});

// Route for rendering admin page (restricted to authenticated admins)
app.get("/adminpage", isAuthenticated, isAdmin, (req, res) => {
  const query = "SELECT * FROM products";
  connection.query(query, (err, products) => {
    if (err) {
      console.error("Error retrieving products:", err);
      res.status(500).send("Error retrieving products");
      return;
    }
    res.render("adminpage", { products }); // Render adminpage and pass products data
  });
});

app.get("/adminpage/vieworder", isAuthenticated, isAdmin, (req, res) => {
    const query = "SELECT * FROM orders";
    connection.query(query, (err, orders) => {
        if (err) {
            console.log(err);
            res.status(500).send("Error fetching orders");
            return;
        }
        
        res.render("vieworder", { orders: orders });
    });
});

// Import necessary modules and set up your Express app

// Route for handling deletion of orders
app.post("/adminpage/deleteorder/:orderId", isAuthenticated, isAdmin, (req, res) => {
    const orderId = req.params.orderId;

    // Perform deletion in the database
    const query = "DELETE FROM orders WHERE id = ?";
    connection.query(query, [orderId], (err, result) => {
        if (err) {
            console.error("Error deleting order:", err);
            res.status(500).send("Error deleting order");
            return;
        }

        // Send response indicating success
        res.status(200).send("Order deleted successfully");
    });
});

// Route for rendering add product form (restricted to authenticated admins)
app.get("/adminpage/addproduct", isAuthenticated, isAdmin, (req, res) => {
  res.render("addproduct");
});

// Route for handling form submission to add product with image upload
app.post(
  "/adminpage/addproduct",
  isAuthenticated,
  isAdmin,
  upload.single("gambar"),
  (req, res) => {
    const { judul, deskripsi, harga, kategori } = req.body;
    const image = req.file.filename; // Get the filename of the uploaded image

    // Insert product into the database
    const query =
      "INSERT INTO products (product_name, product_desc, product_price, product_image, product_type) VALUES (?, ?, ?, ?, ?)";
    connection.query(
      query,
      [judul, deskripsi, harga, image, kategori],
      (err, result) => {
        if (err) {
          console.error("Error inserting product:", err);
          res.status(500).send("Error adding product");
          return;
        }
        console.log("Product added successfully");
        res.redirect("/adminpage"); // Redirect to admin page after adding product
      }
    );
  }
);

// Route for handling form submission to edit product including image upload
app.post(
  "/adminpage/editproduct/:id",
  isAuthenticated,
  isAdmin,
  upload.single("gambar"),
  (req, res) => {
    const productId = req.params.id;
    const { judul, deskripsi, harga, kategori } = req.body;
    let image = req.file ? req.file.filename : null; // Get the filename of the uploaded image, if any

    // Update product in the database
    let query =
      "UPDATE products SET product_name = ?, product_desc = ?, product_price = ?, product_type = ?";
    let params = [judul, deskripsi, harga, kategori];

    // Append image update to query if image is uploaded
    if (image) {
      query += ", product_image = ?";
      params.push(image);
    }

    query += " WHERE id = ?";
    params.push(productId);

    connection.query(query, params, (err, result) => {
      if (err) {
        console.error("Error updating product:", err);
        res.status(500).send("Error updating product");
        return;
      }
      console.log("Product updated successfully");
      res.redirect("/adminpage"); // Redirect to admin page after updating product
    });
  }
);

// Route for deleting a product
app.post(
  "/adminpage/deleteproduct/:id",
  isAuthenticated,
  isAdmin,
  (req, res) => {
    const productId = req.params.id;

    // Query to delete product by id
    const query = "DELETE FROM products WHERE id = ?";
    connection.query(query, [productId], (err, result) => {
      if (err) {
        console.error("Error deleting product:", err);
        res.status(500).send("Error deleting product");
        return;
      }
      console.log("Product deleted successfully");
      res.redirect("/adminpage"); // Redirect to admin page after deletion
    });
  }
);

// Route for rendering edit product form
app.get("/adminpage/editproduct/:id", isAuthenticated, isAdmin, (req, res) => {
  const productId = req.params.id;

  // Query to fetch product details by id
  const query = "SELECT * FROM products WHERE id = ?";
  connection.query(query, [productId], (err, product) => {
    if (err) {
      console.error("Error retrieving product:", err);
      res.status(500).send("Error retrieving product");
      return;
    }
    if (product.length === 0) {
      res.status(404).send("Product not found");
      return;
    }
    // Render editproduct.ejs and pass product data
    res.render("editproduct", { product: product[0] });
  });
});

// Route for handling form submission to update product details
app.post("/adminpage/editproduct/:id", isAuthenticated, isAdmin, (req, res) => {
  const productId = req.params.id;
  const { judul, deskripsi, harga } = req.body;

  // Query to update product details by id
  const query =
    "UPDATE products SET product_name = ?, product_desc = ?, product_price = ? WHERE id = ?";
  connection.query(
    query,
    [judul, deskripsi, harga, productId],
    (err, result) => {
      if (err) {
        console.error("Error updating product:", err);
        res.status(500).send("Error updating product");
        return;
      }
      console.log("Product updated successfully");
      res.redirect("/adminpage"); // Redirect to admin page after update
    }
  );
});

// Route for rendering buyproduct.ejs with product details
app.get("/buyproduct/:productId", isAuthenticated, (req, res) => {
  const productId = req.params.productId;
  // Fetch product details from database
  const query = "SELECT * FROM products WHERE id = ?";
  connection.query(query, [productId], (err, product) => {
    if (err) {
      console.error("Error retrieving product:", err);
      res.status(500).send("Error retrieving product");
      return;
    }
    if (product.length === 0) {
      res.status(404).send("Product not found");
      return;
    }
    res.render("buyproduct", { product: product[0] });
  });
});

// Route for handling form submission to buy product
app.post("/buyproduct/:productid", isAuthenticated, (req, res) => {
    const userId = req.session.passport.user;
    const productId = req.params.productid;
    const { quantity } = req.body;

    // Fetch user details from the database
    const userQuery = "SELECT * FROM users WHERE id = ?";
    connection.query(userQuery, [userId], (err, userResults) => {
        if (err) {
            console.error("Error fetching user details:", err);
            res.status(500).send("Error fetching user details");
            return;
        }

        if (userResults.length === 0) {
            res.status(404).send("User not found");
            return;
        }

        // User data
        const userData = userResults[0]; // Assuming user data is in the first row of results

        // Fetch product details from the database
        const productQuery = "SELECT * FROM products WHERE id = ?";
        connection.query(productQuery, [productId], (err, productResults) => {
            if (err) {
                console.error("Error fetching product details:", err);
                res.status(500).send("Error fetching product details");
                return;
            }

            if (productResults.length === 0) {
                res.status(404).send("Product not found");
                return;
            }

            // Product data
            const productData = productResults[0];

            // Prepare order data
            const orderData = {
                buyer_username: userData.username,
                buyer_email: userData.email,
                buyer_no_telp: userData.no_telp, // Adjust field name based on your database
                order_quantity: quantity,
                product_id: productData.id,
                product_name: productData.product_name,
                product_price: parseFloat(productData.product_price), // Ensure price is converted to float
            };
            
            // Insert order into database
            const insertQuery = "INSERT INTO orders SET ?";
            connection.query(insertQuery, orderData, (err, insertResult) => {
                if (err) {
                    console.error("Error inserting order:", err);
                    res.status(500).send("Error inserting order");
                    return;
                }

                // Redirect to home page or a success page
                res.redirect("/");
            });
        });
    });
});


// POST route for handling signin form submission
app.post(
  "/signin",
  ensureAuthenticated,
  passport.authenticate("local", {
    successRedirect: "/home", // Redirect to home page on successful login
    failureRedirect: "/signin", // Redirect back to signin page on failure
  })
);

// POST route for handling signup form submission
app.post("/signup", ensureAuthenticated, async (req, res) => {
  const { email, no_telp, username, gender, fullname, address, password } =
    req.body;
  const lowerCasedEmail = email.toLowerCase();
  const lowerCasedUsername = username.toLowerCase();
  const role = "user";
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Store username, hashedPassword, and other details in your database
    const sql =
      "INSERT INTO users (email, no_telp, username, gender, fullname, address, password, role) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    connection.query(
      sql,
      [
        lowerCasedEmail,
        no_telp,
        lowerCasedUsername,
        gender,
        fullname,
        address,
        hashedPassword,
        role,
      ],
      (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).send("Error saving user");
          return;
        }
        console.log("User registered successfully");
        res.redirect("/signin"); // Redirect to signin page after successful registration
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// Route for rendering signup.ejs
app.get("/signup", ensureAuthenticated, (req, res) => {
  res.render("signup");
});

// POST route for handling logout
app.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Logout failed");
    }
    res.redirect("/signin"); // Redirect to signin page after logout
  });
});

// Start server
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
