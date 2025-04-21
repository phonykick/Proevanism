"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const path_1 = __importDefault(require("path"));
const sqlite3_1 = __importDefault(require("sqlite3")); // Import sqlite3
const multer_1 = __importDefault(require("multer")); // Import multer
const fs_1 = __importDefault(require("fs")); // Import fs for directory creation
const express_session_1 = __importDefault(require("express-session")); // Import express-session
const passport_1 = __importDefault(require("passport")); // Import passport
const passport_local_1 = require("passport-local"); // Import LocalStrategy
const bcrypt_1 = __importDefault(require("bcrypt")); // Import bcrypt
// --- Hardcoded User (Replace with DB lookup in production) ---
// IMPORTANT: Generate a strong hash for your actual password!
// You can use an online bcrypt generator or a simple script.
// Example: Run `node -e "console.log(require('bcrypt').hashSync('your_password', 10));"` after installing bcrypt globally or locally.
const ADMIN_USERNAME = 'admin';
// Example hash for password "password" (replace with your actual hash)
const ADMIN_PASSWORD_HASH = '$2b$10$ei9AiTQgVBiwLhuD/D9BhuOGTc1LPdbi2OQYHCBX9OlfR9zPg2oFy'; // Hash for EvanAdmin$ecret99!
// --- TEMPORARY DEBUG LOG --- (Remove before production!)
console.log(`[DEBUG] ADMIN_PASSWORD_HASH loaded as: ${ADMIN_PASSWORD_HASH}`);
// --- Upload Directory Setup ---
// Correct path: Go up one level from dist/ to the project root
const uploadDir = path_1.default.resolve(__dirname, '../public/uploads/gallery');
// Ensure upload directory exists
if (!fs_1.default.existsSync(uploadDir)) {
    fs_1.default.mkdirSync(uploadDir, { recursive: true });
    console.log(`Created upload directory: ${uploadDir}`);
}
// --- End Upload Directory Setup ---
// --- Multer Configuration ---
const storage = multer_1.default.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Add timestamp to filename to avoid conflicts
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path_1.default.extname(file.originalname));
    }
});
const upload = (0, multer_1.default)({ storage: storage });
// --- End Multer Configuration ---
// --- Database Setup ---
sqlite3_1.default.verbose(); // Enable verbose mode for detailed logs
// Correct path: Go up one level from dist/ to the project root
const dbPath = path_1.default.resolve(__dirname, '../database.db');
const db = new sqlite3_1.default.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    }
    else {
        console.log('Connected to the SQLite database.');
        // Create table for gallery images if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS gallery_images (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT NOT NULL,
      filepath TEXT NOT NULL UNIQUE,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
            if (err) {
                console.error('Error creating table:', err.message);
            }
            else {
                console.log('Gallery images table ready.');
            }
        });
    }
});
// --- End Database Setup ---
const app = (0, express_1.default)();
const port = process.env.PORT || 3000; // Use environment variable or default to 3000
// --- Session Configuration ---
// WARNING: Use a strong, environment-variable-based secret in production!
app.use((0, express_session_1.default)({
    secret: 'your-very-secret-key-replace-in-prod', // Replace with a real secret!
    resave: false, // Don't save session if unmodified
    saveUninitialized: false, // Don't create session until something stored
    // Configure session store for production (e.g., connect-sqlite3)
    // cookie: { secure: true } // Enable secure cookies in production (requires HTTPS)
}));
// --- End Session Configuration ---
// --- Passport Configuration ---
app.use(passport_1.default.initialize()); // Initialize Passport
app.use(passport_1.default.session()); // Enable session support for Passport
// Configure Passport strategies (e.g., LocalStrategy) later
// Configure user serialization/deserialization later
// --- End Passport Configuration ---
// --- Passport Strategy Configuration ---
passport_1.default.use(new passport_local_1.Strategy((username, password, done) => __awaiter(void 0, void 0, void 0, function* () {
    console.log(`Attempting login for username: ${username}`);
    // In production, look up user in the database here
    if (username === ADMIN_USERNAME) {
        try {
            console.log('Comparing password against stored hash...');
            console.log(`Received password string: [${password}]`);
            console.log(`Using hash: [${ADMIN_PASSWORD_HASH}]`);
            const match = yield bcrypt_1.default.compare(password, ADMIN_PASSWORD_HASH);
            console.log(`Password match result: ${match}`);
            if (match) {
                // Passwords match
                console.log('Password matched. Calling done(null, user).');
                const user = { id: 1, username: ADMIN_USERNAME }; // Hardcoded user object
                return done(null, user);
            }
            else {
                // Passwords don't match
                console.log('Password did not match. Calling done(null, false).');
                return done(null, false, { message: 'Incorrect password.' });
            }
        }
        catch (err) {
            console.error('Error during password comparison:', err);
            return done(err);
        }
    }
    else {
        // Username not found
        console.log('Username not found. Calling done(null, false).');
        return done(null, false, { message: 'Incorrect username.' });
    }
})));
// --- Passport Serialization/Deserialization ---
// Stores user ID in session
passport_1.default.serializeUser((user, done) => {
    done(null, user.id);
});
// Retrieves user details from session ID
passport_1.default.deserializeUser((id, done) => __awaiter(void 0, void 0, void 0, function* () {
    // In production, fetch user from database using id
    if (id === 1) { // Our hardcoded admin user has id 1
        const user = { id: 1, username: ADMIN_USERNAME };
        done(null, user);
    }
    else {
        done(new Error('User not found during deserialization.'), null);
    }
}));
// --- End Passport Serialization/Deserialization ---
// --- Authentication Middleware ---
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { // Passport adds this method
        return next();
    }
    // If not authenticated
    // Check if it's an API request or a page request
    if (req.originalUrl.startsWith('/api/')) {
        res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
    }
    else {
        // Redirect HTML requests to the login page (we'll create this)
        res.redirect('/login.html');
    }
}
// --- End Authentication Middleware ---
// Middleware to parse JSON bodies
app.use(express_1.default.json());
// Middleware to parse URL-encoded bodies
app.use(express_1.default.urlencoded({ extended: true }));
// --- Authentication Routes ---
// Login POST route
app.post('/login', passport_1.default.authenticate('local', {
    successRedirect: '/admin.html', // Redirect to admin panel on success
    failureRedirect: '/login.html', // Redirect back to login on failure
    // failureFlash: true // Optional: use connect-flash for flash messages
}));
// Logout POST route
app.post('/logout', (req, res, next) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect('/login.html'); // Redirect to login page after logout
    });
});
// --- End Authentication Routes ---
// Serve static files (like HTML, CSS, frontend JS) from the root and public directories
app.use(express_1.default.static(path_1.default.join(__dirname, '../'))); // Corrected: Serve files from project root (relative to dist/)
app.use(express_1.default.static(path_1.default.join(__dirname, '../public'))); // Corrected: Serve files from public/ (relative to dist/)
// Add db object to request for use in handlers (optional but can be useful)
app.use((req, res, next) => {
    req.db = db;
    next();
});
// Simple route for testing
app.get('/api/hello', (req, res) => {
    res.json({ message: 'Hello from the backend!' });
});
// POST route for uploading gallery images
app.post('/api/gallery/upload', isAuthenticated, upload.single('imageFile'), (req, res) => {
    if (!req.file) {
        res.status(400).json({ success: false, message: 'No file uploaded.' });
        return;
    }
    const filename = req.file.filename;
    // Store relative path for easier serving later
    const relativeFilePath = path_1.default.join('uploads/gallery', filename).replace(/\\/g, '/');
    const absoluteFilePath = req.file.path; // Store absolute path for potential deletion
    const sql = `INSERT INTO gallery_images (filename, filepath) VALUES (?, ?)`;
    db.run(sql, [filename, relativeFilePath], function (err) {
        if (err) {
            console.error('Error inserting image into database:', err.message);
            // Clean up uploaded file if DB insert fails
            fs_1.default.unlink(absoluteFilePath, (unlinkErr) => {
                if (unlinkErr)
                    console.error('Error deleting file after DB error:', unlinkErr);
            });
            res.status(500).json({ success: false, message: 'Database error.' });
            return;
        }
        console.log(`Image ${filename} uploaded and added to DB with ID ${this.lastID}`);
        res.json({ success: true, message: 'File uploaded successfully!', file: { filename, filepath: relativeFilePath } });
        return;
    });
});
// GET route to retrieve all gallery images
app.get('/api/gallery/images', (req, res) => {
    const sql = `SELECT id, filename, filepath, uploaded_at FROM gallery_images ORDER BY uploaded_at DESC`;
    db.all(sql, [], (err, rows) => {
        if (err) {
            console.error('Error fetching images from database:', err.message);
            res.status(500).json({ success: false, message: 'Database error.' });
            return;
        }
        res.json({ success: true, images: rows });
        return;
    });
});
// DELETE route to remove a gallery image by ID
app.delete('/api/gallery/images/:id', isAuthenticated, (req, res) => {
    const imageId = req.params.id;
    // 1. Find the image record to get the filepath
    const findSql = `SELECT filepath FROM gallery_images WHERE id = ?`;
    db.get(findSql, [imageId], (err, row) => {
        if (err) {
            console.error('Error finding image before delete:', err.message);
            res.status(500).json({ success: false, message: 'Database error while finding image.' });
            return;
        }
        if (!row) {
            res.status(404).json({ success: false, message: 'Image not found.' });
            return;
        }
        const relativeFilePath = row.filepath;
        // Construct absolute path for deletion (relative to project root)
        const absoluteFilePath = path_1.default.resolve(__dirname, '../../public', relativeFilePath);
        // 2. Delete the physical file
        fs_1.default.unlink(absoluteFilePath, (unlinkErr) => {
            if (unlinkErr && unlinkErr.code !== 'ENOENT') { // Ignore error if file already not found
                console.error(`Error deleting file ${absoluteFilePath}:`, unlinkErr.message);
                // Decide if you want to stop or proceed to delete DB record anyway
                // For now, we'll stop and report the file system error.
                res.status(500).json({ success: false, message: 'Error deleting image file.' });
                return;
            }
            if (!unlinkErr) {
                console.log(`Deleted file: ${absoluteFilePath}`);
            }
            else {
                console.log(`File not found, proceeding to delete DB record: ${absoluteFilePath}`);
            }
            // 3. Delete the database record
            const deleteSql = `DELETE FROM gallery_images WHERE id = ?`;
            db.run(deleteSql, [imageId], function (dbErr) {
                if (dbErr) {
                    console.error('Error deleting image from database:', dbErr.message);
                    res.status(500).json({ success: false, message: 'Database error while deleting record.' });
                    return;
                }
                if (this.changes === 0) {
                    // This case should technically be caught by the earlier check, but good practice
                    console.warn(`Attempted to delete non-existent DB record ID: ${imageId}`);
                    res.status(404).json({ success: false, message: 'Image record not found in DB for deletion.' });
                    return;
                }
                console.log(`Deleted image record ID: ${imageId}`);
                res.json({ success: true, message: 'Image deleted successfully.' });
                return;
            });
        });
    });
});
// --- Protected Page Routes ---
// Protect the admin page itself
app.get('/admin.html', isAuthenticated, (req, res) => {
    // If authenticated, serve the admin.html file
    // Note: express.static already handles serving static files if placed correctly.
    // This route primarily ensures authentication before the static handler serves it.
    // We might need to adjust static file serving if this causes issues.
    // For now, let the static handler do its job after auth check.
    // Alternatively, explicitly send the file:
    res.sendFile(path_1.default.resolve(__dirname, '../../admin.html'));
});
// --- End Protected Page Routes ---
// --- Protected Gallery API Routes ---
// Apply isAuthenticated middleware to protect these routes
app.post('/api/gallery/upload', isAuthenticated, upload.single('imageFile'), (req, res) => {
    if (!req.file) {
        res.status(400).json({ success: false, message: 'No file uploaded.' });
        return;
    }
    const filename = req.file.filename;
    // Store relative path for easier serving later
    const relativeFilePath = path_1.default.join('uploads/gallery', filename).replace(/\\/g, '/');
    const absoluteFilePath = req.file.path; // Store absolute path for potential deletion
    const sql = `INSERT INTO gallery_images (filename, filepath) VALUES (?, ?)`;
    db.run(sql, [filename, relativeFilePath], function (err) {
        if (err) {
            console.error('Error inserting image into database:', err.message);
            // Clean up uploaded file if DB insert fails
            fs_1.default.unlink(absoluteFilePath, (unlinkErr) => {
                if (unlinkErr)
                    console.error('Error deleting file after DB error:', unlinkErr);
            });
            res.status(500).json({ success: false, message: 'Database error.' });
            return;
        }
        console.log(`Image ${filename} uploaded and added to DB with ID ${this.lastID}`);
        res.json({ success: true, message: 'File uploaded successfully!', file: { filename, filepath: relativeFilePath } });
        return;
    });
});
// Start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
