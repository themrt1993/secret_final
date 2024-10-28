require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const https = require('https');
const fs = require('fs');
const app = express();

// Add these requires at the top of the file
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Serve static files
app.use(express.static('public'));

// Passport configuration
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://secret.tvoelkner.de/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const userDir = path.join(__dirname, 'uploads', req.user.id);
        fs.mkdirSync(userDir, { recursive: true });
        cb(null, userDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        // Preserve the original file extension
        const ext = path.extname(file.originalname);
        cb(null, file.originalname.split('.')[0] + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Allow txt and image files
        if (file.mimetype === 'text/plain' || 
            file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only .txt and image files are allowed!'));
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/dashboard');
    }
);

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});

app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        // Create an HTML template with user data
        const userData = {
            name: req.user.displayName,
            firstName: req.user.name.givenName,
            lastName: req.user.name.familyName,
            email: req.user.emails[0].value,
            picture: req.user.photos[0].value
        };
        
        // Add route to get user data
        app.get('/api/user-data', (req, res) => {
            if (req.isAuthenticated()) {
                res.json(userData);
            } else {
                res.status(401).json({ error: 'Not authenticated' });
            }
        });
        
        res.sendFile(__dirname + '/public/dashboard.html');
    } else {
        res.redirect('/');
    }
});

app.post('/upload', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    upload.single('file')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ error: 'File upload error: ' + err.message });
        } else if (err) {
            return res.status(400).json({ error: err.message });
        }
        
        res.json({ 
            message: 'File uploaded successfully',
            filename: req.file.filename
        });
    });
});

// Add these routes after your existing routes

// Serve contents page
app.get('/contents', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(__dirname + '/public/contents.html');
    } else {
        res.redirect('/');
    }
});

// Get user's files
app.get('/api/files', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const userDir = path.join(__dirname, 'uploads', req.user.id);
    
    try {
        if (!fs.existsSync(userDir)) {
            return res.json({ files: [] });
        }

        const files = fs.readdirSync(userDir)
            .filter(file => {
                const ext = path.extname(file).toLowerCase();
                return ['.txt', '.jpg', '.jpeg', '.png', '.gif', '.bmp'].includes(ext);
            })
            .filter(file => !file.endsWith('.meta')) // Exclude metadata files
            .map(filename => {
                const filePath = path.join(userDir, filename);
                const stats = fs.statSync(filePath);
                const metaPath = filePath + '.meta';
                const isEncrypted = fs.existsSync(metaPath);
                const ext = path.extname(filename).toLowerCase();
                const isImage = ['.jpg', '.jpeg', '.png', '.gif', '.bmp'].includes(ext);
                
                return {
                    filename,
                    originalName: filename.split('-')[0] + ext,
                    uploadDate: stats.mtime,
                    isEncrypted,
                    fileType: isImage ? 'image' : 'text'
                };
            });

        res.json({ files });
    } catch (error) {
        console.error('Error reading files:', error);
        res.status(500).json({ error: 'Error reading files: ' + error.message });
    }
});

// Download file
app.get('/download/:filename', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const userDir = path.join(__dirname, 'uploads', req.user.id);
    const filePath = path.join(userDir, req.params.filename);

    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).json({ error: 'File not found' });
    }
});

// Delete file
app.delete('/api/files/:filename', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const userDir = path.join(__dirname, 'uploads', req.user.id);
    const filePath = path.join(userDir, req.params.filename);

    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            res.json({ message: 'File deleted successfully' });
        } else {
            res.status(404).json({ error: 'File not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error deleting file' });
    }
});

// Get file content
app.get('/api/files/:filename/content', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const userDir = path.join(__dirname, 'uploads', req.user.id);
    const filePath = path.join(userDir, path.basename(req.params.filename));
    const metaPath = filePath + '.meta';

    try {
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        const isEncrypted = fs.existsSync(metaPath);
        if (isEncrypted) {
            return res.status(403).json({ 
                error: 'File is encrypted. Please decrypt it first.',
                isEncrypted: true 
            });
        }

        const ext = path.extname(filePath).toLowerCase();
        const isImage = ['.jpg', '.jpeg', '.png', '.gif', '.bmp'].includes(ext);

        if (isImage) {
            const content = fs.readFileSync(filePath);
            res.set('Content-Type', `image/${ext.slice(1)}`);
            res.send(content);
        } else {
            const content = fs.readFileSync(filePath, 'utf8');
            res.set('Content-Type', 'text/plain');
            res.send(content);
        }
    } catch (error) {
        console.error('Error reading file:', error);
        res.status(500).json({ error: 'Error reading file: ' + error.message });
    }
});

// Update file content
app.put('/api/files/:filename/content', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const userDir = path.join(__dirname, 'uploads', req.user.id);
    const filePath = path.join(userDir, req.params.filename);

    try {
        let content = '';
        req.on('data', chunk => {
            content += chunk.toString();
        });

        req.on('end', () => {
            if (fs.existsSync(filePath)) {
                fs.writeFileSync(filePath, content, 'utf8');
                res.json({ message: 'File updated successfully' });
            } else {
                res.status(404).json({ error: 'File not found' });
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Error updating file' });
    }
});

// Add these helper functions
function encryptData(data, password, algorithm = 'aes-256-gcm') {
    try {
        const salt = crypto.randomBytes(16);
        const key = crypto.scryptSync(password, salt, 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        
        let encrypted = Buffer.concat([
            cipher.update(data),
            cipher.final()
        ]);
        
        const authTag = cipher.getAuthTag();
        
        return {
            encrypted: encrypted.toString('base64'),
            salt: salt.toString('hex'),
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            algorithm
        };
    } catch (error) {
        console.error('Encryption function error:', error);
        throw new Error('Encryption failed');
    }
}

function decryptData(encryptedData, password) {
    try {
        const salt = Buffer.from(encryptedData.salt, 'hex');
        const iv = Buffer.from(encryptedData.iv, 'hex');
        const authTag = Buffer.from(encryptedData.authTag, 'hex');
        const encrypted = Buffer.from(encryptedData.encrypted, 'base64');
        const algorithm = encryptedData.algorithm;
        
        const key = crypto.scryptSync(password, salt, 32);
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        decipher.setAuthTag(authTag);
        
        const decrypted = Buffer.concat([
            decipher.update(encrypted),
            decipher.final()
        ]);
        
        return decrypted;
    } catch (error) {
        console.error('Decryption function error:', error);
        throw new Error('Decryption failed');
    }
}

// Add these new routes
app.post('/api/files/encrypt', express.json(), async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { filename, password, algorithm } = req.body;
    if (!filename || !password) {
        return res.status(400).json({ error: 'Filename and password are required' });
    }

    const userDir = path.join(__dirname, 'uploads', req.user.id);
    const filePath = path.join(userDir, path.basename(filename));
    const metaPath = filePath + '.meta';

    try {
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        const ext = path.extname(filePath).toLowerCase();
        const isImage = ['.jpg', '.jpeg', '.png', '.gif', '.bmp'].includes(ext);
        
        // Read file content as buffer for both text and binary files
        const content = fs.readFileSync(filePath);
        
        // Encrypt the content
        const encryptedData = encryptData(content, password, algorithm);

        // Save encrypted content
        fs.writeFileSync(filePath, encryptedData.encrypted);
        
        // Save metadata
        fs.writeFileSync(metaPath, JSON.stringify({
            isEncrypted: true,
            salt: encryptedData.salt,
            iv: encryptedData.iv,
            authTag: encryptedData.authTag,
            algorithm: encryptedData.algorithm,
            originalType: isImage ? 'image' : 'text'
        }));

        res.json({ message: 'File encrypted successfully' });
    } catch (error) {
        console.error('Encryption error:', error);
        res.status(500).json({ error: 'Encryption failed: ' + error.message });
    }
});

app.post('/api/files/decrypt', express.json(), async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { filename, password } = req.body;
    if (!filename || !password) {
        return res.status(400).json({ error: 'Filename and password are required' });
    }

    const userDir = path.join(__dirname, 'uploads', req.user.id);
    const filePath = path.join(userDir, path.basename(filename));
    const metaPath = filePath + '.meta';

    try {
        if (!fs.existsSync(filePath) || !fs.existsSync(metaPath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        const metadata = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
        const encryptedContent = fs.readFileSync(filePath, 'utf8');

        const decrypted = decryptData({
            encrypted: encryptedContent,
            salt: metadata.salt,
            iv: metadata.iv,
            authTag: metadata.authTag,
            algorithm: metadata.algorithm
        }, password);

        // Write decrypted content based on original file type
        if (metadata.originalType === 'image') {
            fs.writeFileSync(filePath, decrypted);
        } else {
            fs.writeFileSync(filePath, decrypted.toString('utf8'));
        }
        
        fs.unlinkSync(metaPath);

        res.json({ message: 'File decrypted successfully' });
    } catch (error) {
        console.error('Decryption error:', error);
        res.status(400).json({ error: 'Decryption failed. Wrong password?' });
    }
});

// Read the certificate and key files
const options = {
    key: fs.readFileSync('/etc/letsencrypt/live/secret.tvoelkner.de/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/secret.tvoelkner.de/fullchain.pem')
};

const PORT = process.env.PORT || 443;  // Change port to 443
https.createServer(options, app).listen(PORT, () => {
    console.log(`Server is running on https://secret.tvoelkner.de`);
});
