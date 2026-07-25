const express = require("express");
const cors = require("cors");
require("dotenv").config();

const crypto = require('crypto');
const https = require('https');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Resend } = require('resend');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const adminRoutes = require('./routes/adminRoutes');

const subscriptionRoutes = require('./routes/subscriptionRoutes');
const progressRoutes = require('./routes/progressRoutes');
const interviewRoutes = require('./routes/interviewRoutes');
const analyticsRoutes = require('./routes/analyticsRoutes');
const notificationRoutes = require('./routes/notificationRoutes');
const testRoutes = require('./routes/testRoutes');
const { recomputeAndSaveReadiness, getReadinessLabel } = require('./utils/readiness');
const { isSubscriptionActive } = require('./utils/subscriptionUtils');
const Notification = require('./models/Notification');
const emailService = require('./services/emailService');
const User = require('./models/User');
const Lead = require('./models/Lead');
const Subscription = require('./models/Subscription');
const Transaction = require('./models/Transaction');
const ActivityLog = require('./models/ActivityLog');
const authMiddleware = require('./middleware/authMiddleware');


// Admin middleware — only allows users with isAdmin flag
const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.userId).select('isAdmin');
        if (!user || !user.isAdmin) {
            return res.status(403).json({ success: false, message: 'Access denied. Admin only.' });
        }
        next();
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Server error' });
    }
};

const app = express();
const PORT = process.env.PORT || 5000;
const BCRYPT_ROUNDS = 12;

// Chat limits / OTP config
const FREE_CHAT_LIMIT = 3;
const OTP_TTL_MS = 10 * 60 * 1000;          // 10 minutes
const SUBSCRIPTION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// ==========================
// REQUIRED ENVIRONMENT VARS
// ==========================
if (!process.env.MONGO_URI) {
    console.error('❌ Error: MONGO_URI is not defined in the .env file.');
    process.exit(1);
}

// A strong, secret-only signing key is mandatory. No insecure fallback.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('❌ Error: JWT_SECRET is missing or too weak.');
    console.error('👉 Tip: Add a long random JWT_SECRET (32+ chars) to your .env file.');
    console.error('   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
    process.exit(1);
}

const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const isProduction = process.env.NODE_ENV === 'production';

// Pre-computed dummy hash used in the login route to prevent user-enumeration
// timing attacks. Generated once at startup with the real cost factor.
let DUMMY_HASH = null;
(async () => {
    DUMMY_HASH = await bcrypt.hash('__dummy__', BCRYPT_ROUNDS);
})();

// ==========================
// SECURITY MIDDLEWARE
// ==========================
app.use(helmet());

// CORS: restrict to configured origins. ALLOWED_ORIGINS is a comma-separated list.
// Requests with no Origin header (curl, mobile apps) are allowed through.
// file:// pages send Origin: null — treated as allowed for local development.
// Always permits localhost:3000 and localhost:5000 for frontend dev servers.
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(o => o.trim())
    .filter(Boolean);

// These origins are always permitted (dev frontend + file:// local pages).
const ALWAYS_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000'
];

app.use(cors({
    origin(origin, callback) {
        // No Origin header: non-browser request (curl, Postman, mobile) — allow.
        if (!origin) return callback(null, true);
        // file:// pages send Origin: "null" as a string literal — allow for local dev.
        if (origin === 'null') return callback(null, true);
        // Always-allowed dev origins.
        if (ALWAYS_ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        // Explicit allow-list from environment.
        if (allowedOrigins.length > 0 && allowedOrigins.includes(origin)) return callback(null, true);
        // In development with no explicit list, allow any localhost/127.0.0.1 port.
        if (!isProduction && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
            return callback(null, true);
        }
        return callback(new Error('Not allowed by CORS'));
    },
    credentials: true
}));

// Body parsers. profilePicture may carry base64 image data, so allow a larger limit.
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// ==========================
// REQUEST LOGGER (password-safe)
// ==========================
const SENSITIVE_KEYS = ['password', 'currentPassword', 'newPassword', 'token', 'otp', 'profilePicture'];

function redactBody(body) {
    if (!body || typeof body !== 'object') return body;
    const clone = Array.isArray(body) ? [...body] : { ...body };
    for (const key of Object.keys(clone)) {
        if (SENSITIVE_KEYS.includes(key)) {
            clone[key] = '[REDACTED]';
        }
    }
    return clone;
}

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    if (req.method !== 'GET' && req.body && Object.keys(req.body).length > 0) {
        console.log('Request Body:', JSON.stringify(redactBody(req.body)));
    }
    next();
});

// ==========================
// RATE LIMITERS
// ==========================
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,                  // 20 auth attempts per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many attempts. Please try again later.' }
});

const otpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,                  // 10 OTP requests per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many OTP requests. Please try again later.' }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many requests. Please try again later.' }
});

app.use('/api/', apiLimiter);

// ==========================
// ROUTES
// ==========================
app.use('/api/subscription', require('./routes/subscriptionRoutes'));
app.use('/api/progress', require('./routes/progressRoutes'));
app.use('/api/interview', interviewRoutes);
app.use('/api/ai-chat', require('./routes/aiChatRoutes'));
app.use('/api/analytics', analyticsRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/admin', authMiddleware, adminMiddleware, adminRoutes);

// Dev/Test route to reset a user's subscription back to free tier.
app.use('/api/test', testRoutes);



// ==========================
// MONGODB CONNECTION
// ==========================
mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 5000
})
    .then(() => {
        console.log('✅ Connected to MongoDB Atlas');
        console.log('Using Database:', mongoose.connection.name);
        console.log('Using Collection for Users:', User.collection.name);
    })
    .catch(err => {
        console.error('❌ MongoDB connection error:', err.message);
        if (err.message.includes('IP not whitelisted') || err.message.includes('Could not connect to any servers')) {
            console.error('👉 Tip: Ensure your IP address is whitelisted in MongoDB Atlas.');
        } else if (err.message.includes('Authentication failed')) {
            console.error('👉 Tip: Check your database username and password in the .env file.');
        }
        process.exit(1);
    });

// ==========================
// HELPERS
// ==========================
function signToken(user) {
    return jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
    );
}

// Generic server error responder: logs detail, hides internals from the client.
function serverError(res, context, error) {
    console.error(`${context}:`, error);
    const payload = { success: false, message: 'Server error' };
    if (!isProduction) payload.error = error.message; // detail only in dev
    return res.status(500).json(payload);
}

// Validation result handler
function handleValidation(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: errors.array()[0].msg
        });
    }
    next();
}

// Compute calendar-day streak update given the previous login date.
function computeStreak(currentStreak, lastLoginDate, now) {
    let newStreak = currentStreak || 1;
    if (lastLoginDate) {
        const lastDate = new Date(lastLoginDate).setHours(0, 0, 0, 0);
        const todayDate = new Date(now).setHours(0, 0, 0, 0);
        const diffCalendarDays = Math.round((todayDate - lastDate) / 86400000);
        if (diffCalendarDays === 1) {
            newStreak += 1;
        } else if (diffCalendarDays > 1) {
            newStreak = 1;
        }
    } else {
        newStreak = 1;
    }
    return newStreak;
}



// Build the standard user payload returned to clients (never includes password).
function buildUserPayload(user) {
    return {
        id: user._id,
        email: user.email,
        name: user.name,
        selectedPath: user.selectedPath,
        selectedLevel: user.selectedLevel,
        skills: user.skills,
        competencyScore: user.competencyScore,
        experienceRank: user.experienceRank,
        readinessScore: user.readinessScore || 0,
        dailyStreak: user.dailyStreak,
        lastActivePage: user.lastActivePage,
        quizScores: user.quizScores,
        completedModules: user.completedModules,
        completedRoadmaps: user.completedRoadmaps || [],
        completedLessons: user.completedLessons || [],
        onboardingCompleted: user.onboardingCompleted || false,
        interests: user.interests || [],
        emailVerified: user.emailVerified || false,
        phoneNumber: user.phoneNumber || null,
        profilePicture: user.profilePicture || null,
        education: user.education || null,
        careerInterests: user.careerInterests || [],
        chatMessagesUsed: user.chatMessagesUsed || 0,
        chatSubscriptionActive: user.chatSubscriptionActive || false,
        isPro: isSubscriptionActive(user),
        isAdmin: user.isAdmin || false
    };
}

// Validate a date-of-birth string. Returns an error message string, or null if valid.
// Rules: not in the future, age >= 13, age <= 120.
function validateDob(dob) {
    if (dob === undefined || dob === null || dob === '') return null; // optional
    if (typeof dob !== 'string') return 'Invalid date of birth';

    const birth = new Date(dob);
    if (isNaN(birth.getTime())) return 'Invalid date of birth';

    const now = new Date();
    if (birth.getTime() > now.getTime()) {
        return 'Date of birth cannot be in the future';
    }

    // Compute precise age in years.
    let age = now.getFullYear() - birth.getFullYear();
    const monthDiff = now.getMonth() - birth.getMonth();
    if (monthDiff < 0 || (monthDiff === 0 && now.getDate() < birth.getDate())) {
        age--;
    }

    if (age < 13) return 'You must be at least 13 years old';
    if (age > 120) return 'Please enter a valid date of birth (age cannot exceed 120 years)';

    return null;
}

// Generate a 6-digit numeric OTP and its SHA-256 hash for storage.
function generateOTP() {
    const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const hash = crypto.createHash('sha256').update(otp).digest('hex');
    return { otp, hash };
}

function hashOTP(otp) {
    return crypto.createHash('sha256').update(String(otp)).digest('hex');
}

// ── Email provider setup ──
// Priority: SMTP (Gmail) first, Resend second, console-only fallback.
const resendApiKey = process.env.EMAIL_API_KEY;
let resend = null;
if (resendApiKey) {
    resend = new Resend(resendApiKey);
    console.log('✅ Resend email provider configured.');
} else {
    console.warn('⚠️  EMAIL_API_KEY not set — Resend disabled.');
}

const smtpConfigured =
    process.env.SMTP_USER &&
    process.env.SMTP_PASS &&
    process.env.SMTP_PASS !== 'YOUR_GMAIL_APP_PASSWORD_HERE';

let smtpTransporter = null;
if (smtpConfigured) {
    smtpTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        secure: process.env.SMTP_SECURE === 'true',
        auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        tls: { rejectUnauthorized: false }
    });
    console.log(`✅ SMTP email provider configured (${process.env.SMTP_USER}).`);
} else {
    console.warn('⚠️  SMTP_PASS not set or placeholder — SMTP disabled.');
}

const emailHtml = (otp) => `
<!DOCTYPE html><html><body style="font-family:'Inter',Arial,sans-serif;background:#f8fafc;padding:40px 20px;">
<div style="max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:32px 24px;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:1.6rem;font-weight:800;">🎓 Xyverra</h1>
        <p style="color:rgba(255,255,255,0.85);margin:8px 0 0;font-size:0.95rem;">AI-Powered Career Guidance</p>
    </div>
    <div style="padding:32px 24px;">
        <h2 style="margin:0 0 8px;font-size:1.2rem;color:#1e293b;">Verify your email address</h2>
        <p style="color:#64748b;margin:0 0 24px;line-height:1.6;">Use the 6-digit code below to verify your Xyverra account. It expires in <strong>10 minutes</strong>.</p>
        <div style="background:#f1f5f9;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
            <span style="font-size:2.5rem;font-weight:900;letter-spacing:0.3em;color:#4f46e5;font-family:monospace;">${otp}</span>
        </div>
        <p style="color:#94a3b8;font-size:0.8rem;margin:0;">If you didn't create an account, you can safely ignore this email.</p>
    </div>
</div>
</body></html>`;

async function sendOtpEmail(email, otp) {
    console.log(`\n📧 Sending OTP to ${email}: ${otp}  (valid ${OTP_TTL_MS / 60000} min)`);

    // ─ Try SMTP (Gmail) first ─
    if (smtpTransporter) {
        try {
            await smtpTransporter.sendMail({
                from: process.env.EMAIL_FROM || `"Xyverra" <${process.env.SMTP_USER}>`,
                to: email,
                subject: 'Your Xyverra verification code',
                text: `Your Xyverra verification code is: ${otp}\n\nThis code expires in 10 minutes.`,
                html: emailHtml(otp)
            });
            console.log(`✅ OTP email sent via SMTP to ${email}`);
            return;
        } catch (smtpErr) {
            console.error('❌ SMTP send failed:', smtpErr.message);
            console.log('🔄 Falling back to Resend...');
        }
    }

    // ─ Try Resend as fallback ─
    if (resend) {
        try {
            const fromAddress = process.env.EMAIL_FROM_ADDRESS || 'onboarding@resend.dev';
            const { data, error } = await resend.emails.send({
                from: `Xyverra <${fromAddress}>`,
                to: [email],
                subject: 'Your Xyverra verification code',
                html: emailHtml(otp),
            });
            if (error) {
                console.error('❌ Resend API Error:', JSON.stringify(error));
            } else {
                console.log(`✅ OTP email sent via Resend to ${email}. ID: ${data?.id}`);
            }
            return;
        } catch (resendErr) {
            console.error('❌ Resend send failed:', resendErr.message);
        }
    }

    // ─ No email provider configured ─
    console.error('❌ No email provider configured. OTP for manual testing:', otp);
    console.error('   Add SMTP_PASS (Gmail App Password) OR EMAIL_API_KEY (Resend) to your .env');
}

const resetEmailHtml = (resetUrl) => `
<!DOCTYPE html><html><body style="font-family:'Inter',Arial,sans-serif;background:#f8fafc;padding:40px 20px;">
<div style="max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
    <div style="background:linear-gradient(135deg,#4f46e5,#7c3aed);padding:32px 24px;text-align:center;">
        <h1 style="color:#fff;margin:0;font-size:1.6rem;font-weight:800;">🎓 Xyverra</h1>
        <p style="color:rgba(255,255,255,0.85);margin:8px 0 0;font-size:0.95rem;">AI-Powered Career Guidance</p>
    </div>
    <div style="padding:32px 24px;">
        <h2 style="margin:0 0 8px;font-size:1.2rem;color:#1e293b;">Reset Your Password</h2>
        <p style="color:#64748b;margin:0 0 24px;line-height:1.6;">You are receiving this email because you (or someone else) requested a password reset for your account. Please click the button below to complete the process. This link expires in <strong>15 minutes</strong>.</p>
        <div style="text-align:center;margin-bottom:24px;">
            <a href="${resetUrl}" style="background-color:#4f46e5;color:#fff;padding:12px 24px;text-decoration:none;border-radius:8px;font-weight:bold;display:inline-block;">Reset Password</a>
        </div>
        <p style="color:#94a3b8;font-size:0.8rem;margin:0;">If you didn't request this, you can safely ignore this email.</p>
    </div>
</div>
</body></html>`;

async function sendResetEmail(email, resetUrl) {
    console.log(`\n📧 Sending Password Reset to ${email}`);
    
    if (smtpTransporter) {
        try {
            await smtpTransporter.sendMail({
                from: process.env.EMAIL_FROM || `"Xyverra" <${process.env.SMTP_USER}>`,
                to: email,
                subject: 'Xyverra Password Reset',
                text: `You requested a password reset. Please click this link to reset your password: ${resetUrl}\n\nThis link expires in 15 minutes.`,
                html: resetEmailHtml(resetUrl)
            });
            console.log(`✅ Reset email sent via SMTP to ${email}`);
            return;
        } catch (smtpErr) {
            console.error('❌ SMTP send failed:', smtpErr.message);
            console.log('🔄 Falling back to Resend...');
        }
    }

    if (resend) {
        try {
            const fromAddress = process.env.EMAIL_FROM_ADDRESS || 'onboarding@resend.dev';
            const { data, error } = await resend.emails.send({
                from: `Xyverra <${fromAddress}>`,
                to: [email],
                subject: 'Xyverra Password Reset',
                html: resetEmailHtml(resetUrl),
            });
            if (error) {
                console.error('❌ Resend API Error:', JSON.stringify(error));
            } else {
                console.log(`✅ Reset email sent via Resend to ${email}. ID: ${data?.id}`);
            }
            return;
        } catch (resendErr) {
            console.error('❌ Resend send failed:', resendErr.message);
        }
    }

    console.error('❌ No email provider configured. Reset URL for manual testing:', resetUrl);
}



// ==========================
// PUBLIC ROUTES
// ==========================
app.get('/', (req, res) => {
    res.json({ message: 'Xyverra API is running' });
});

app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'UP',
        db: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        time: new Date().toISOString(),
        dbName: mongoose.connection.name
    });
});

// ==========================
// LEAD CAPTURE ROUTE (Landing Page Waitlist/Newsletter)
// ==========================
app.post(
    '/api/leads/subscribe',
    // Note: apiLimiter is already applied globally to every /api/* route
    // (app.use('/api/', apiLimiter) above). Re-applying it here double-counted
    // every request against the same shared store, silently halving this
    // route's effective limit versus every other route.
    [
        body('email').isEmail().withMessage('Please provide a valid email address')
            .bail().customSanitizer(v => v.trim().toLowerCase())
    ],
    handleValidation,
    async (req, res) => {
        try {
            const { email } = req.body;
            
            // Check if already subscribed
            const existingLead = await Lead.findOne({ email });
            if (existingLead) {
                return res.status(409).json({
                    success: false,
                    message: 'You are already on the waitlist. Keep an eye on your inbox!'
                });
            }

            // Save new lead
            await Lead.create({ email });
            
            return res.status(201).json({
                success: true,
                message: 'Successfully joined the waitlist!'
            });
        } catch (error) {
            return serverError(res, 'Lead Subscription Error', error);
        }
    }
);

// ==========================
// REGISTER ROUTE
// ==========================
app.post(
    '/api/auth/register',
    authLimiter,
    [
        body('email').isEmail().withMessage('A valid email is required')
            .bail().customSanitizer(v => v.trim().toLowerCase()),
        body('password')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
            .matches(/\d/).withMessage('Password must contain at least one number')
            .matches(/[a-zA-Z]/).withMessage('Password must contain at least one letter'),
        body('name').optional().trim().isLength({ max: 100 }),
        body('skills').optional().isArray().withMessage('Skills must be an array')
    ],
    handleValidation,
    async (req, res) => {
        try {
            const { email, password, name, skills, dob } = req.body;

            // DOB validation (optional field)
            const dobError = validateDob(dob);
            if (dobError) {
                return res.status(400).json({ success: false, message: dobError });
            }

            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(409).json({
                    success: false,
                    message: 'An account with this email already exists'
                });
            }

            const hashedPassword = await bcrypt.hash(password, BCRYPT_ROUNDS);

            const newUser = await User.create({
                email,
                password: hashedPassword,
                name: name || email.split('@')[0],
                skills: Array.isArray(skills) ? skills : [],
                dob: dob || null,
                dailyStreak: 1,
                lastLoginDate: new Date()
            });

            console.log('✅ User saved successfully with ID:', newUser._id);

            const token = signToken(newUser);

            await ActivityLog.create({
                userId: newUser._id,
                userName: newUser.name,
                userEmail: newUser.email,
                actionType: 'Registration',
                details: 'User registered a new account',
                badgeColor: 'badge-green'
            }).catch(e => console.error('ActivityLog Error:', e));

            res.status(201).json({
                success: true,
                message: 'User registered successfully',
                token,
                user: buildUserPayload(newUser)
            });
        } catch (error) {
            return serverError(res, 'Registration Error', error);
        }
    }
);

// ==========================
// LOGIN ROUTE
// ==========================
app.post(
    '/api/auth/login',
    authLimiter,
    [
        body('email').isEmail().withMessage('A valid email is required')
            .bail().customSanitizer(v => v.trim().toLowerCase()),
        body('password').notEmpty().withMessage('Password is required')
    ],
    handleValidation,
    async (req, res) => {
        try {
            const { email, password } = req.body;

            const user = await User.findOne({ email }).populate('activeSubscription');

            // Use a generic message and always run a compare to reduce user enumeration
            // and timing differences between "no user" and "wrong password".
            if (!user) {
                // Always run a compare against the pre-computed dummy hash to equalise
                // timing between "no user found" and "wrong password" paths.
                await bcrypt.compare(password, DUMMY_HASH || '$2a$12$dummyhashfortimingequalisation0');
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({
                    success: false,
                    message: 'Invalid credentials'
                });
            }

            const now = new Date();
            user.dailyStreak = computeStreak(user.dailyStreak, user.lastLoginDate, now);
            user.lastLoginDate = now;
            await user.save();

            const token = signToken(user);

            await ActivityLog.create({
                userId: user._id,
                userName: user.name,
                userEmail: user.email,
                actionType: 'Login',
                details: 'User logged in successfully',
                badgeColor: 'badge-blue'
            }).catch(e => console.error('ActivityLog Error:', e));

            res.json({
                success: true,
                message: 'Login successful',
                token,
                user: buildUserPayload(user)
            });
        } catch (error) {
            return serverError(res, 'Login Error', error);
        }
    }
);

// ==========================
// FORGOT PASSWORD ROUTE
// ==========================
app.post(
    '/api/auth/forgot-password',
    authLimiter,
    [
        body('email').isEmail().withMessage('A valid email is required')
            .bail().customSanitizer(v => v.trim().toLowerCase())
    ],
    handleValidation,
    async (req, res) => {
        try {
            const { email } = req.body;
            const user = await User.findOne({ email });

            // To prevent email enumeration, we always return success message 
            // even if the user doesn't exist.
            if (!user) {
                return res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent.' });
            }

            // Generate Token
            const resetToken = crypto.randomBytes(32).toString('hex');
            const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

            // Set token and expiry (15 mins)
            user.resetPasswordToken = hashedToken;
            user.resetPasswordExpire = Date.now() + 15 * 60 * 1000;
            await user.save();

            // Construct Reset URL
            let referer = req.headers.referer;
            let resetUrl;
            if (referer) {
                // Ensure we replace forgot-password.html with reset-password.html
                // even if there are query parameters or hashes in the referer
                let base = referer.split('?')[0].split('#')[0];
                if (base.endsWith('forgot-password.html')) {
                    resetUrl = base.replace('forgot-password.html', 'reset-password.html') + `?token=${resetToken}`;
                } else {
                    // Fallback if accessed differently
                    let clientUrl = req.headers.origin && req.headers.origin !== 'null' ? req.headers.origin : 'http://localhost:3000';
                    resetUrl = `${clientUrl}/Frontend/reset-password.html?token=${resetToken}`;
                }
            } else {
                let clientUrl = req.headers.origin && req.headers.origin !== 'null' ? req.headers.origin : 'http://localhost:3000';
                resetUrl = `${clientUrl}/reset-password.html?token=${resetToken}`;
            }

            await sendResetEmail(user.email, resetUrl);

            const responsePayload = { success: true, message: 'If an account with that email exists, a reset link has been sent.' };
            if (!isProduction) {
                responsePayload._dev_resetUrl = resetUrl;
                responsePayload._dev_note = 'Reset URL visible in development mode only';
            }
            res.json(responsePayload);
        } catch (error) {
            return serverError(res, 'Forgot Password Error', error);
        }
    }
);

// ==========================
// RESET PASSWORD ROUTE
// ==========================
app.post(
    '/api/auth/reset-password',
    authLimiter,
    [
        body('token').notEmpty().withMessage('Token is required'),
        body('newPassword')
            .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
            .matches(/\d/).withMessage('Password must contain at least one number')
            .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
            .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
            .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Password must contain at least one special character')
    ],
    handleValidation,
    async (req, res) => {
        try {
            const { token, newPassword } = req.body;

            const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

            const user = await User.findOne({
                resetPasswordToken: hashedToken,
                resetPasswordExpire: { $gt: Date.now() }
            });

            if (!user) {
                return res.status(400).json({ success: false, message: 'This password reset link is invalid or has expired.' });
            }

            user.password = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;
            await user.save();

            res.json({ success: true, message: 'Password reset successful. Please log in with your new password.' });
        } catch (error) {
            return serverError(res, 'Reset Password Error', error);
        }
    }
);

// ==========================
// SEND OTP ROUTE (auth required)
// Generates a 6-digit OTP, stores its hash + expiry, and "sends" it via email stub.
// ==========================
app.post('/api/auth/send-otp', authMiddleware, otpLimiter, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (user.emailVerified) {
            return res.json({ success: true, message: 'Email is already verified' });
        }

        const { otp, hash } = generateOTP();
        user.emailVerificationOTP = hash;
        user.emailVerificationExpiry = new Date(Date.now() + OTP_TTL_MS);
        await user.save();

        sendOtpEmail(user.email, otp);

        // In development, return the OTP in the response so the flow is testable
        // without a real email service. This is NEVER done in production.
        const responsePayload = { success: true, message: 'OTP sent to your email' };
        responsePayload._dev_otp = otp;
        responsePayload._dev_note = 'OTP is provided directly because the email domain is unverified in Resend Sandbox';
        return res.json(responsePayload);
    } catch (error) {
        return serverError(res, 'Send OTP Error', error);
    }
});

// ==========================
// RESEND OTP ROUTE (auth required)
// Regenerates a fresh OTP and resets the expiry window.
// ==========================
app.post('/api/auth/resend-otp', authMiddleware, otpLimiter, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        if (user.emailVerified) {
            return res.json({ success: true, message: 'Email is already verified' });
        }

        const { otp, hash } = generateOTP();
        user.emailVerificationOTP = hash;
        user.emailVerificationExpiry = new Date(Date.now() + OTP_TTL_MS);
        await user.save();

        sendOtpEmail(user.email, otp);

        const responsePayload = { success: true, message: 'A new OTP has been sent to your email' };
        responsePayload._dev_otp = otp;
        responsePayload._dev_note = 'OTP is provided directly because the email domain is unverified in Resend Sandbox';
        return res.json(responsePayload);
    } catch (error) {
        return serverError(res, 'Resend OTP Error', error);
    }
});

// ==========================
// VERIFY OTP ROUTE (auth required)
// Verifies the submitted OTP, marks the email as verified, and issues a fresh token.
// ==========================
app.post(
    '/api/auth/verify-otp',
    otpLimiter,
    authMiddleware,
    [
        body('otp').trim().isLength({ min: 6, max: 6 }).withMessage('A valid 6-digit OTP is required')
            .bail().isNumeric().withMessage('A valid 6-digit OTP is required')
    ],
    handleValidation,
    async (req, res) => {
        try {
            const { otp } = req.body;

            const user = await User.findById(req.user.userId);
            if (!user) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            if (user.emailVerified) {
                const token = signToken(user);
                return res.json({ success: true, message: 'Email already verified', token });
            }

            if (!user.emailVerificationOTP || !user.emailVerificationExpiry) {
                return res.status(400).json({ success: false, message: 'No OTP requested. Please request a new one.' });
            }

            if (new Date(user.emailVerificationExpiry).getTime() < Date.now()) {
                return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
            }

            if (hashOTP(otp) !== user.emailVerificationOTP) {
                return res.status(400).json({ success: false, message: 'Invalid OTP' });
            }

            user.emailVerified = true;
            user.emailVerificationOTP = null;
            user.emailVerificationExpiry = null;
            await user.save();

            const token = signToken(user);
            return res.json({ success: true, message: 'Email verified successfully', token });
        } catch (error) {
            return serverError(res, 'Verify OTP Error', error);
        }
    }
);

// ==========================
// CHAT USAGE ROUTE (auth required)
// Returns the user's chat message usage and subscription status.
// ==========================
app.get('/api/chat/usage', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
            .select('chatMessagesUsed chatSubscriptionActive chatSubscriptionExpiry activeSubscription')
            .populate('activeSubscription');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const subscriber = isSubscriptionActive(user);

        return res.json({
            success: true,
            messagesUsed: user.chatMessagesUsed || 0,
            freeLimit: FREE_CHAT_LIMIT,
            isSubscriber: subscriber,
            subscriptionExpiry: user.chatSubscriptionExpiry || null,
            blocked: !subscriber && (user.chatMessagesUsed || 0) >= FREE_CHAT_LIMIT
        });
    } catch (error) {
        return serverError(res, 'Chat Usage Error', error);
    }
});

// ==========================
// GROQ AI CHAT ROUTE (auth required)
// Enforces free-tier limit, calls Groq API, stores chat history.
// ==========================

// In-memory chat history per user session (resets on server restart)
// For persistence use MongoDB
async function callGroq(userMessage, chatHistory, userContext) {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) {
        console.warn('GROQ_API_KEY not set — AI responses unavailable');
        return null;
    }

    const systemPrompt = `You are an expert AI Career Counselor for Xyverra, an AI-powered career guidance platform.
You help students and professionals navigate their tech career journey with personalized, actionable advice.

User Context:
- Name: ${userContext.name || 'User'}
- Selected Career Path: ${userContext.selectedPath || 'Not yet selected'}
- Current Level: ${userContext.selectedLevel || 'Not specified'}
- Skills: ${(userContext.skills || []).join(', ') || 'Not specified'}

CRITICAL INSTRUCTIONS:
1. You MUST ONLY answer questions related to the following topics: career guidance, skills, learning paths, job roles, resumes, interview preparation, certifications, career roadmaps, education, internships, and professional development.
2. If the user asks about ANYTHING else (e.g., movies, politics, jokes, math homework, general coding unrelated to career, random conversations, general trivia), you MUST politely refuse.
3. If you refuse, you MUST reply with this exact phrase and nothing else:
"I'm Xyverra's Career Mentor AI. I can only help with career guidance, learning paths, skills, resumes, interviews, and professional growth. Please ask a career-related question."
4. Do not hallucinate or attempt to answer unrelated prompts.

When answering valid questions, be encouraging, professional, and concise. Format responses with **bold** for key terms and - bullet points for lists.`;

    const messages = [
        { role: 'system', content: systemPrompt },
        ...chatHistory.slice(-10).map(m => ({
            role: m.role === 'user' ? 'user' : 'assistant',
            content: m.content
        })),
        { role: 'user', content: userMessage }
    ];

    const requestBody = JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages,
        temperature: 0.7,
        max_tokens: 800,
        top_p: 0.9
    });

    return new Promise((resolve) => {
        const options = {
            hostname: 'api.groq.com',
            path: '/openai/v1/chat/completions',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${apiKey}`,
                'Content-Length': Buffer.byteLength(requestBody)
            },
            timeout: 20000
        };

        const req = https.request(options, (groqRes) => {
            let data = '';
            groqRes.on('data', chunk => data += chunk);
            groqRes.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    if (parsed.choices && parsed.choices[0] && parsed.choices[0].message) {
                        resolve(parsed.choices[0].message.content);
                    } else if (parsed.error) {
                        console.error('Groq API error:', parsed.error.message);
                        resolve(null);
                    } else {
                        resolve(null);
                    }
                } catch (e) {
                    console.error('Groq parse error:', e.message);
                    resolve(null);
                }
            });
        });

        req.on('error', (e) => { console.error('Groq request error:', e.message); resolve(null); });
        req.on('timeout', () => { req.destroy(); resolve(null); });
        req.write(requestBody);
        req.end();
    });
}


app.post('/api/chat/message', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate('activeSubscription');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const subscriber = isSubscriptionActive(user);

        // Free users are capped. Block once they have used their allowance.
        if (!subscriber && (user.chatMessagesUsed || 0) >= FREE_CHAT_LIMIT) {
            return res.status(403).json({
                success: false,
                blocked: true,
                messagesUsed: user.chatMessagesUsed || 0,
                freeLimit: FREE_CHAT_LIMIT,
                isSubscriber: false,
                message: 'Free message limit reached. Subscribe to continue chatting.'
            });
        }

        const { content, history } = req.body;
        if (!content || typeof content !== 'string' || content.trim().length === 0) {
            return res.status(400).json({ success: false, message: 'Message content is required' });
        }

        // Use atomic $inc to avoid race conditions on chatMessagesUsed.
        const updated = await User.findByIdAndUpdate(
            req.user.userId,
            { $inc: { chatMessagesUsed: 1 } },
            { returnDocument: 'after' }
        );

        // Call Groq AI (llama-3.3-70b) for response
        const chatHistory = Array.isArray(history) ? history : [];
        const userContext = {
            name: user.name,
            selectedPath: user.selectedPath,
            selectedLevel: user.selectedLevel,
            skills: user.skills
        };

        const aiResponse = await callGroq(content.trim(), chatHistory, userContext);

        return res.json({
            success: true,
            blocked: false,
            messagesUsed: updated ? updated.chatMessagesUsed : (user.chatMessagesUsed || 0) + 1,
            freeLimit: FREE_CHAT_LIMIT,
            isSubscriber: subscriber,
            aiResponse: aiResponse // null if Groq unavailable (fallback to frontend keyword engine)
        });
    } catch (error) {
        return serverError(res, 'Chat Message Error', error);
    }
});

// ==========================
// SAVE CHAT HISTORY (auth required)
// ==========================
app.post('/api/chat/save-history', authMiddleware, async (req, res) => {
    try {
        const { history } = req.body;
        if (!Array.isArray(history)) {
            return res.status(400).json({ success: false, message: 'History must be an array' });
        }
        // Store in user document (last 50 messages)
        const trimmed = history.slice(-50);
        await User.findByIdAndUpdate(req.user.userId, { $set: { chatHistory: trimmed } });
        return res.json({ success: true });
    } catch (error) {
        return serverError(res, 'Save Chat History Error', error);
    }
});

// ==========================
// GET CHAT HISTORY (auth required)
// ==========================
app.get('/api/chat/history', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('chatHistory chatMessagesUsed chatSubscriptionActive chatSubscriptionExpiry');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        return res.json({
            success: true,
            history: user.chatHistory || [],
            messagesUsed: user.chatMessagesUsed || 0,
            isSubscriber: isSubscriptionActive(user)
        });
    } catch (error) {
        return serverError(res, 'Get Chat History Error', error);
    }
});

// ==========================
// CHAT SUBSCRIBE ROUTE (auth required)
// Demo implementation — activates a 30-day subscription.
// In production this must be replaced with real payment verification (e.g. Stripe webhook).
// ==========================
app.post('/api/chat/subscribe', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const expiry = new Date(Date.now() + SUBSCRIPTION_DURATION_MS);
        user.chatSubscriptionActive = true;
        user.chatSubscriptionExpiry = expiry;
        user.chatMessagesUsed = 0; // Reset usage counter on subscription
        await user.save();

        // 🔔 Send a welcome Pro notification
        try {
            const { createNotification } = require('./routes/notificationRoutes');
            await createNotification(req.user.userId, {
                title: '🎉 You are now a Pro member!',
                message: 'Welcome to XYVERRA Pro! You now have unlimited AI counselor messages, advanced analytics, mock interviews, and more.',
                type: 'success',
                actionLink: 'dashboard.html'
            });
        } catch (ne) { console.warn('Notification error:', ne); }

        return res.json({
            success: true,
            message: 'Premium subscription activated! Enjoy unlimited conversations.',
            subscriptionExpiry: expiry,
            isSubscriber: true,
            durationDays: 30
        });
    } catch (error) {
        return serverError(res, 'Subscribe Error', error);
    }
});

// ==========================
// SAVE PATH ROUTE (auth required, scoped to token user)
// ==========================
app.post('/api/user/save-path', authMiddleware, async (req, res) => {
    try {
        const { selectedPath } = req.body;
        if (!selectedPath || typeof selectedPath !== 'string') {
            return res.status(400).json({
                success: false,
                message: 'Selected path is required'
            });
        }
        const trimmedPath = selectedPath.trim();

        const existingUser = await User.findById(req.user.userId).select('selectedPath');
        if (!existingUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Switching to a genuinely different roadmap — wipe all progress tied to
        // the old path so Dashboard, Progress, Skill Gap and Career Analytics only
        // ever reflect the newly chosen roadmap, never leftover data from the last one.
        const isSwitchingRoadmap = !!existingUser.selectedPath && existingUser.selectedPath !== trimmedPath;

        const update = { selectedPath: trimmedPath };
        if (isSwitchingRoadmap) {
            update.completedModules = [];
            update.completedLessons = [];
            update.quizScores = {};
            update.studiedLessons = {};
            update.competencyScore = 0;
            update.readinessScore = 0;
            update.analyticsData = {};
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { $set: update },
            { returnDocument: 'after' }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // 🔔 Notify user of path selection
        try {
            const { createNotification } = require('./routes/notificationRoutes');
            await createNotification(req.user.userId, {
                title: `🎯 Career path set: ${selectedPath}`,
                message: `Your personalized roadmap and skill gap analysis for ${selectedPath} are ready. Time to start learning!`,
                type: 'info',
                actionLink: 'roadmap.html'
            });
        } catch (ne) { console.warn('Notification error:', ne); }

        const readinessScore = await recomputeAndSaveReadiness(req.user.userId);

        return res.json({
            success: true,
            message: 'Path saved successfully',
            selectedPath: updatedUser.selectedPath,
            readinessScore
        });
    } catch (error) {
        return serverError(res, 'Save Path Error', error);
    }
});

// ==========================
// SAVE CAREER DISCOVERY RESULTS (auth required)
// Persists questionnaire answers + recommended careers so they survive
// across devices and are visible to admins.
// ==========================
app.post('/api/user/save-career-assessment', authMiddleware, async (req, res) => {
    try {
        const { answers, recommendedCareers } = req.body;

        const update = {};
        if (answers && typeof answers === 'object') update.careerAssessmentAnswers = answers;
        if (Array.isArray(recommendedCareers)) update.recommendedCareers = recommendedCareers;

        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { $set: update },
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        return res.json({ success: true, message: 'Career assessment saved' });
    } catch (error) {
        return serverError(res, 'Save Career Assessment Error', error);
    }
});

// ==========================
// SAVE LEVEL ROUTE (auth required, scoped to token user)
// ==========================
app.post('/api/user/save-level', authMiddleware, async (req, res) => {
    try {
        const { selectedLevel } = req.body;
        if (!selectedLevel || typeof selectedLevel !== 'string') {
            return res.status(400).json({
                success: false,
                message: 'Selected level is required'
            });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { selectedLevel: selectedLevel.trim() },
            { returnDocument: 'after' }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        return res.json({
            success: true,
            message: 'Level saved successfully',
            selectedLevel: updatedUser.selectedLevel
        });
    } catch (error) {
        return serverError(res, 'Save Level Error', error);
    }
});

// ==========================
// SAVE SKILLS ROUTE (auth required, scoped to token user)
// ==========================
app.post('/api/user/save-skills', authMiddleware, async (req, res) => {
    try {
        const { skills } = req.body;
        if (!Array.isArray(skills)) {
            return res.status(400).json({
                success: false,
                message: 'Skills array is required'
            });
        }

        const cleanSkills = skills
            .filter(s => typeof s === 'string')
            .map(s => s.trim())
            .slice(0, 200);

        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { skills: cleanSkills },
            { returnDocument: 'after' }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        return res.json({
            success: true,
            message: 'Skills saved successfully',
            skills: updatedUser.skills
        });
    } catch (error) {
        return serverError(res, 'Save Skills Error', error);
    }
});

// ==========================
// GET PROFILE
// ==========================

app.get('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate('activeSubscription');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({ success: true, user: buildUserPayload(user) });
    } catch (error) {
        return serverError(res, 'Get Profile Error', error);
    }
});

// Alias: /api/user/me → same as /api/user/profile (used by dashboard.js)
app.get('/api/user/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).populate('activeSubscription');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        // Always recompute rather than trust the last-persisted value — keeps
        // the Job Readiness Score accurate even if it went stale (e.g. leftover
        // from before a roadmap switch) without waiting on a quiz/lesson event.
        user.readinessScore = await recomputeAndSaveReadiness(req.user.userId);
        res.json({ success: true, user: buildUserPayload(user) });
    } catch (error) {
        return serverError(res, 'Get Me Error', error);
    }
});

// ==========================
// UPDATE PROFILE
// ==========================
app.put('/api/user/profile', authMiddleware, async (req, res) => {
    try {
        const allowedUpdates = [
            'name', 'selectedLevel', 'skills', 'dob', 'lastActivePage',
            'quizScores', 'profilePicture', 'careerInterests',
            'interests', 'timeline', 'weeklyHours'
        ];

        // DOB validation if provided.
        if (Object.prototype.hasOwnProperty.call(req.body, 'dob')) {
            const dobStr = req.body.dob;
            if (dobStr) {
                const dobDate = new Date(dobStr + 'T00:00:00');
                if (isNaN(dobDate.getTime())) {
                    return res.status(400).json({ success: false, message: 'Invalid Date of Birth.' });
                }
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                if (dobDate > today) {
                    return res.status(400).json({ success: false, message: 'Date of birth cannot be in the future.' });
                }
            }
        }

        const updates = {};
        for (const key of Object.keys(req.body)) {
            if (allowedUpdates.includes(key)) {
                updates[key] = req.body[key];
            }
        }

        const user = await User.findByIdAndUpdate(
            req.user.userId,
            { $set: updates },
            { returnDocument: 'after', runValidators: true }
        ).select('-password -emailVerificationOTP -emailVerificationExpiry');

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        return serverError(res, 'Update Profile Error', error);
    }
});

// ==========================
// SAVE QUIZ SCORE ROUTE (auth required)
// Saves quiz score keyed by moduleId (preferred) or skill name.
// Uses atomic $inc for experienceRank to avoid read-modify-write race conditions.
// Uses computeStreak() for dailyStreak rather than unconditional increment.
// ==========================
app.post('/api/user/save-quiz', authMiddleware, async (req, res) => {
    try {
        // Accept moduleId as the canonical key; fall back to skill for backwards compatibility.
        const { skill, moduleId, score } = req.body;
        const quizKey = moduleId || skill;
        if (!quizKey || typeof score !== 'number') {
            return res.status(400).json({ success: false, message: 'moduleId (or skill) and score are required' });
        }
        if (score < 0 || score > 100) {
            return res.status(400).json({ success: false, message: 'Score must be between 0 and 100' });
        }

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Store score under the key (xyverra_quiz_scores format: moduleId → score)
        user.quizScores.set(quizKey, score);

        // Atomic XP increment to avoid race conditions — apply via $inc after save
        // Scaled to a max of 10 XP for a skill assessment
        const xpGain = Math.round((score / 100) * 10);

        // Re-calculate competency score (average of all quizzes with score >= 80)
        let totalScore = 0;
        let count = 0;
        user.quizScores.forEach((val) => {
            if (val >= 80) {
                totalScore += val;
                count++;
            }
        });
        user.competencyScore = count > 0 ? Math.floor(totalScore / count) : user.competencyScore;

        // NOTE: do NOT update lastLoginDate here — streak is tied to actual logins,
        // not quiz completions. Updating lastLoginDate in quiz save caused streak inflation
        // (users could gain streak credit on days they only took a quiz, not logged in).

        // Merge completed modules
        const moduleIds = moduleId ? [moduleId] : quizKey.split(',');
        moduleIds.forEach(id => {
            if (typeof id === 'string' && !user.completedModules.includes(id)) {
                user.completedModules.push(id);
            }
        });

        await user.save();

        // Apply XP gain atomically to avoid race condition on experienceRank
        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { $inc: { experienceRank: xpGain } },
            { returnDocument: 'after' }
        );

        return res.json({
            success: true,
            message: 'Quiz saved successfully',
            experienceRank: updatedUser ? updatedUser.experienceRank : user.experienceRank + xpGain,
            competencyScore: user.competencyScore,
            dailyStreak: user.dailyStreak,
            completedModules: user.completedModules
        });
    } catch (error) {
        return serverError(res, 'Save Quiz Error', error);
    }
});

// ==========================
// SAVE COMPLETED MODULES ROUTE (auth required)
// ==========================
app.post('/api/user/save-completed-modules', authMiddleware, async (req, res) => {
    try {
        const { completedModules } = req.body;
        if (!Array.isArray(completedModules)) {
            return res.status(400).json({ success: false, message: 'completedModules must be an array' });
        }

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Merge: add any new IDs not already present
        completedModules.forEach(id => {
            if (typeof id === 'string' && !user.completedModules.includes(id)) {
                user.completedModules.push(id);
            }
        });

        await user.save();

        return res.json({
            success: true,
            message: 'Completed modules saved',
            completedModules: user.completedModules
        });
    } catch (error) {
        return serverError(res, 'Save Completed Modules Error', error);
    }
});

// ==========================
// SAVE ONBOARDING ROUTE (auth required)
// ==========================
app.post('/api/user/save-onboarding', authMiddleware, async (req, res) => {
    try {
        const { interests, skills, selectedLevel, careerGoal, timeline, weeklyHours } = req.body;

        const updates = { onboardingCompleted: true };

        if (Array.isArray(interests)) {
            updates.interests = interests.slice(0, 20);
        }
        if (Array.isArray(skills)) {
            updates.skills = skills.filter(s => typeof s === 'string').map(s => s.trim()).slice(0, 100);
        }
        if (selectedLevel && typeof selectedLevel === 'string') {
            updates.selectedLevel = selectedLevel.trim();
        }
        if (careerGoal && typeof careerGoal === 'string') {
            updates.careerGoal = careerGoal.trim().slice(0, 300);
        }
        if (timeline && typeof timeline === 'string') {
            updates.timeline = timeline.trim();
        }
        if (weeklyHours && typeof weeklyHours === 'string') {
            updates.weeklyHours = weeklyHours.trim();
        }

        // Set selectedPath from first interest if not already set.
        // Use $setOnInsert-like logic via conditional: only set selectedPath if it is
        // currently null. We do this in a single findByIdAndUpdate using $set with
        // a conditional check via aggregation pipeline update (MongoDB 4.2+).
        // For compatibility we use a regular $set but guard with a separate read-free
        // approach: include selectedPath in the update only when provided by the client,
        // otherwise compute it from interests but only when not already present.
        const INTEREST_TO_PATH = {
            'Web Development': 'Web Development',
            'Full Stack Development': 'Full Stack Development',
            'Backend / APIs': 'Backend / APIs',
            'Data Science': 'Data Science',
            'AI / Machine Learning': 'NLP / AI',
            'AI / ML': 'NLP / AI',
            'Cloud / DevOps': 'Cloud / DevOps',
            'UI/UX Design': 'UI/UX Design',
            'Mobile Development': 'Mobile Development',
            'Cybersecurity': 'Cybersecurity',
            'Data Analytics': 'Data Analytics',
            'AI Engineer': 'AI Engineer'
        };

        // Merge selectedPath from interests into updates for setOnInsert behaviour:
        // use $set for all fields, but for selectedPath use $setOnInsert equivalent by
        // only adding it when the field is currently null — achieved via a single atomic
        // findOneAndUpdate with a filter that requires selectedPath to be null/absent.
        if (interests && interests.length > 0) {
            const derivedPath = INTEREST_TO_PATH[interests[0]] || interests[0];
            // Attempt to set selectedPath only if currently null (atomic, no separate read)
            await User.updateOne(
                { _id: req.user.userId, $or: [{ selectedPath: null }, { selectedPath: { $exists: false } }] },
                { $set: { selectedPath: derivedPath } }
            );
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { $set: updates },
            { returnDocument: 'after' }
        );

        if (!updatedUser) return res.status(404).json({ success: false, message: 'User not found' });

        const readinessScore = await recomputeAndSaveReadiness(req.user.userId);

        return res.json({
            success: true,
            message: 'Onboarding saved successfully',
            selectedPath: updatedUser.selectedPath,
            selectedLevel: updatedUser.selectedLevel,
            onboardingCompleted: updatedUser.onboardingCompleted,
            readinessScore
        });
    } catch (error) {
        return serverError(res, 'Save Onboarding Error', error);
    }
});

// ==========================
// SAVE PAGE ROUTE (auth required)
// ==========================
app.post('/api/user/save-page', authMiddleware, async (req, res) => {
    try {
        const { lastActivePage } = req.body;
        if (!lastActivePage || typeof lastActivePage !== 'string') {
            return res.status(400).json({ success: false, message: 'Page is required' });
        }

        // Sanitize: trim whitespace and enforce max length
        const trimmed = lastActivePage.trim();
        if (trimmed.length === 0) {
            return res.status(400).json({ success: false, message: 'Page is required' });
        }
        if (trimmed.length > 200) {
            return res.status(400).json({ success: false, message: 'Page value too long (max 200 characters)' });
        }

        // Whitelist: allow only safe page path characters (letters, digits, -, _, ., /)
        if (!/^[\w\-./]+$/.test(trimmed)) {
            return res.status(400).json({ success: false, message: 'Invalid page value' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            { lastActivePage: trimmed },
            { returnDocument: 'after' }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        return res.json({
            success: true,
            lastActivePage: updatedUser.lastActivePage
        });
    } catch (error) {
        return serverError(res, 'Save Page Error', error);
    }
});

// ==========================
// MARK MODULE LESSON STUDIED (auth required)
// Records that a specific lesson/course within a module was studied.
// ==========================
app.post('/api/user/mark-lesson-studied', authMiddleware, async (req, res) => {
    try {
        const { courseId, moduleId, timeSpentSeconds } = req.body;
        if (!courseId || typeof courseId !== 'string') {
            return res.status(400).json({ success: false, message: 'courseId is required' });
        }
        if (courseId.trim().length === 0 || courseId.length > 500) {
            return res.status(400).json({ success: false, message: 'courseId must be 1–500 characters' });
        }
        const sanitizedCourseId = courseId.trim();
        const sanitizedModuleId = (moduleId && typeof moduleId === 'string') ? moduleId.trim().slice(0, 200) : null;
        const timeVal = (typeof timeSpentSeconds === 'number' && timeSpentSeconds >= 0)
            ? Math.min(Math.floor(timeSpentSeconds), 86400)  // cap at 24 h
            : 0;

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Persist lesson study record to the database
        user.studiedLessons.set(sanitizedCourseId, Date.now());
        await user.save();

        return res.json({
            success: true,
            message: 'Lesson study recorded',
            courseId: sanitizedCourseId,
            moduleId: sanitizedModuleId,
            timeSpentSeconds: timeVal
        });
    } catch (error) {
        return serverError(res, 'Mark Lesson Error', error);
    }
});

// ==========================
// CHANGE PASSWORD ROUTE
// ==========================
app.put(
    '/api/user/change-password',
    authMiddleware,
    [
        body('currentPassword').notEmpty().withMessage('Current password is required'),
        body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long')
    ],
    handleValidation,
    async (req, res) => {
        try {
            const { currentPassword, newPassword } = req.body;

            const user = await User.findById(req.user.userId);
            if (!user) {
                return res.status(404).json({ success: false, message: 'User not found' });
            }

            const isMatch = await bcrypt.compare(currentPassword, user.password);
            if (!isMatch) {
                return res.status(401).json({ success: false, message: 'Incorrect current password' });
            }

            user.password = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
            await user.save();

            res.json({ success: true, message: 'Password updated successfully' });
        } catch (error) {
            return serverError(res, 'Change Password Error', error);
        }
    }
);

// ==========================
// LOGOUT ROUTE
// With stateless JWTs the server cannot invalidate tokens. This endpoint exists
// for semantic correctness and future token-blocklist support. The client must
// discard its token on logout.
// ==========================
app.post('/api/auth/logout', (req, res) => {
    return res.json({ success: true, message: 'Logged out successfully' });
});

// NOTE: Subscription status/history/create-payment/verify-payment/cancel are all
// handled by routes/subscriptionRoutes.js -> controllers/subscriptionController.js
// (mounted at /api/subscription, server.js:180). That is the single, correct,
// currently-used implementation — duplicate/broken copies that used to live here
// (mismatched Subscription/Transaction field names, causing every call to 500)
// have been removed to avoid dead code and schema drift.

// NOTE: GET /api/admin/users is handled by routes/adminRoutes.js (mounted at
// /api/admin, server.js:180), which enriches each user with progressRecords,
// quizScoresFromProgress, etc. — the data admin.js's Users Management table
// actually depends on. A simpler, unenriched duplicate used to be registered
// here too (dead code, always shadowed); it has been removed.

// ==========================
// ADMIN: GET USER DETAIL
// ==========================
app.get('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.id)
            .select('-password -emailVerificationOTP -emailVerificationExpiry')
            .populate('activeSubscription');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, user });
    } catch (error) {
        return serverError(res, 'Admin User Detail Error', error);
    }
});

// ==========================
// ADMIN: DELETE USER
// ==========================
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        if (req.params.id === req.user.userId) {
            return res.status(400).json({ success: false, message: 'Cannot delete your own admin account.' });
        }

        const userId = req.params.id;
        const deletedUser = await User.findByIdAndDelete(userId);
        if (!deletedUser) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        // Cascade delete every record that references this user, so nothing is
        // left orphaned in the database (Progress, quiz attempts, subscriptions,
        // transactions, activity logs, notifications, interview sessions).
        const Progress = require('./models/Progress');
        const QuizAttempt = require('./models/QuizAttempt');
        const InterviewSession = require('./models/InterviewSession');
        await Promise.all([
            Progress.deleteMany({ userId }),
            QuizAttempt.deleteMany({ userId }),
            Subscription.deleteMany({ userId }),
            Transaction.deleteMany({ userId }),
            ActivityLog.deleteMany({ userId }),
            Notification.deleteMany({ userId }),
            InterviewSession.deleteMany({ userId })
        ]);

        res.json({ success: true, message: 'User and all associated records deleted.' });
    } catch (error) {
        return serverError(res, 'Admin Delete User Error', error);
    }
});

// ==========================
// ADMIN: TOGGLE ADMIN ROLE
// ==========================
app.put('/api/admin/users/:id/toggle-admin', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        user.isAdmin = !user.isAdmin;
        await user.save();
        res.json({ success: true, message: `User is now ${user.isAdmin ? 'an admin' : 'a regular user'}.`, isAdmin: user.isAdmin });
    } catch (error) {
        return serverError(res, 'Admin Toggle Error', error);
    }
});

// NOTE: GET /api/admin/subscriptions is handled by routes/adminRoutes.js
// (mounted at /api/admin, server.js:180), which correctly enriches each
// subscription with userName/userEmail/transaction info using the real
// `userId` schema field. A duplicate used to be registered here too — it was
// both dead code (always shadowed) AND broken (`.populate('user', ...)` when
// the actual Subscription field is `userId`, so it always populated nothing).

// ==========================
// ADMIN: GET ANALYTICS SUMMARY
// ==========================
app.get('/api/admin/analytics', authMiddleware, adminMiddleware, async (req, res) => {
    try {
        const [
            totalUsers,
            verifiedUsers,
            onboardedUsers,
            activeSubscriptions,
            totalRevenue
        ] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ emailVerified: true }),
            User.countDocuments({ onboardingCompleted: true }),
            Subscription.countDocuments({ status: 'active' }),
            Transaction.aggregate([
                { $match: { status: 'success' } },
                { $group: { _id: null, total: { $sum: '$amountNPR' } } }
            ])
        ]);

        // Path distribution
        const pathDistribution = await User.aggregate([
            { $match: { selectedPath: { $ne: null } } },
            { $group: { _id: '$selectedPath', count: { $sum: 1 } } },
            { $sort: { count: -1 } }
        ]);

        // Signups per day (last 7 days)
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const signupsPerDay = await User.aggregate([
            { $match: { createdAt: { $gte: sevenDaysAgo } } },
            {
                $group: {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
                    count: { $sum: 1 }
                }
            },
            { $sort: { '_id': 1 } }
        ]);

        res.json({
            success: true,
            analytics: {
                totalUsers,
                verifiedUsers,
                onboardedUsers,
                activeSubscriptions,
                totalRevenueNPR: totalRevenue.length ? totalRevenue[0].total : 0,
                pathDistribution,
                signupsPerDay
            }
        });
    } catch (error) {
        return serverError(res, 'Admin Analytics Error', error);
    }
});

// ==========================
// NOTE: this file used to contain a second, entirely unused parallel payment
// subsystem (/api/payment/esewa/initiate, /api/payment/esewa/verify,
// /api/payment/status, /api/payment/transactions). Verified via a full
// Frontend/ grep that no page ever calls any /api/payment/* route — the real,
// live checkout flow (subscription.html -> mock-checkout.html ->
// payment-success.html) exclusively uses /api/subscription/create-payment and
// /api/subscription/verify-payment (routes/subscriptionRoutes.js ->
// controllers/subscriptionController.js). Removed to eliminate dead code and
// reduce unnecessary attack surface (an unused, unmaintained payment-adjacent
// API is still a live target). If a real eSewa integration is added later,
// build it as an extension of subscriptionController.js so there is only ever
// one payment code path.

// ==========================
// AI CAREER RECOMMENDATION
// Calls Groq with questionnaire answers → returns top 3 careers with match % and reasons
// ==========================
app.post('/api/ai/recommend-career', authMiddleware, async (req, res) => {
    try {
        const { answers } = req.body;
        if (!answers || typeof answers !== 'object') {
            return res.status(400).json({ success: false, message: 'answers object is required' });
        }

        // Map answer codes to human-readable labels for better AI context
        const answerLabels = {
            q1: {
                systems:  'Building scalable systems',
                creative: 'Designing visual experiences',
                data:     'Finding patterns in data',
                security: 'Finding & fixing vulnerabilities'
            },
            q2: {
                creative: 'Mostly visual & creative',
                logical:  'Mostly logical & analytical',
                balanced: 'A balanced mix of both',
                systems:  'Infrastructure & backend systems'
            },
            q3: {
                high:     'Very comfortable with math/statistics - loves it',
                somewhat: 'Comfortable enough with math',
                low:      'Prefers to avoid heavy math'
            },
            q4: {
                team:        'Highly collaborative teams',
                balanced:    'A balanced mix of team and solo work',
                independent: 'Mostly independent work'
            },
            q5: {
                high:     'Absolutely loves automating workflows',
                somewhat: 'Somewhat interested in automation',
                low:      'Not interested in automation'
            },
            q6: {
                high:     'Very interested in cloud infrastructure & DevOps',
                somewhat: 'Somewhat interested in DevOps',
                low:      'Prefers just writing code'
            },
            q7: {
                fast_job:          'Land a job as fast as possible',
                high_salary:       'Maximise starting salary',
                deep_skill:        'Master a deep technical skill',
                creative_portfolio: 'Build a creative portfolio'
            },
            q8: {
                '5h':  'Less than 5 hours per week',
                '10h': '5-10 hours per week',
                '20h': '10-20 hours per week',
                full:  'Full-time dedication'
            },
            q9: {
                app:           'A consumer app (web or mobile)',
                ai_product:    'An AI-powered tool or assistant',
                secure_system: 'A secure financial/enterprise system',
                data_dashboard:'A data dashboard or analytics tool'
            }
        };

        const readable = {};
        Object.keys(answers).forEach(key => {
            readable[key] = (answerLabels[key] && answerLabels[key][answers[key]]) || answers[key];
        });

        const prompt = `You are a career guidance AI expert. Based on the following user assessment answers, recommend exactly the top 3 tech career paths that best match this person.

User Assessment:
- Primary interest: ${readable.q1 || 'Not answered'}
- Work preference (visual vs logical): ${readable.q2 || 'Not answered'}
- Math comfort level: ${readable.q3 || 'Not answered'}
- Team vs independent work: ${readable.q4 || 'Not answered'}
- Interest in automation/DevOps tools: ${readable.q5 || 'Not answered'}
- Interest in cloud infrastructure: ${readable.q6 || 'Not answered'}
- Primary career goal: ${readable.q7 || 'Not answered'}
- Weekly learning commitment: ${readable.q8 || 'Not answered'}
- Type of product they want to build: ${readable.q9 || 'Not answered'}

Available career paths to choose from:
- Web Development
- UI/UX Design
- Data Science
- Machine Learning
- Cybersecurity
- Cloud / DevOps
- Backend / APIs
- Mobile Development

Return ONLY valid JSON with no markdown, no explanation, no extra text. The response must be exactly this structure:
{
  "recommendations": [
    { "career": "Career Name", "match": 94, "reason": "Brief 1-2 sentence explanation why this matches." },
    { "career": "Career Name", "match": 88, "reason": "Brief 1-2 sentence explanation why this matches." },
    { "career": "Career Name", "match": 81, "reason": "Brief 1-2 sentence explanation why this matches." }
  ]
}

Only pick career names from the available list above. Match percentages should be realistic (70-98 range). Order by match percentage descending.`;

        const apiKey = process.env.GROQ_API_KEY;
        if (!apiKey) {
            return res.status(503).json({ success: false, message: 'AI service not configured' });
        }

        const requestBody = JSON.stringify({
            model: 'llama-3.3-70b-versatile',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.4,
            max_tokens: 600,
            response_format: { type: 'json_object' }
        });

        const aiResult = await new Promise((resolve) => {
            const options = {
                hostname: 'api.groq.com',
                path: '/openai/v1/chat/completions',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`,
                    'Content-Length': Buffer.byteLength(requestBody)
                },
                timeout: 20000
            };

            const groqReq = https.request(options, (groqRes) => {
                let data = '';
                groqRes.on('data', chunk => data += chunk);
                groqRes.on('end', () => {
                    try {
                        const parsed = JSON.parse(data);
                        if (parsed.choices && parsed.choices[0] && parsed.choices[0].message) {
                            const content = parsed.choices[0].message.content;
                            const json = JSON.parse(content);
                            resolve(json);
                        } else {
                            resolve(null);
                        }
                    } catch (e) {
                        console.error('AI Recommend parse error:', e.message);
                        resolve(null);
                    }
                });
            });
            groqReq.on('error', () => resolve(null));
            groqReq.on('timeout', () => { groqReq.destroy(); resolve(null); });
            groqReq.write(requestBody);
            groqReq.end();
        });

        if (!aiResult || !Array.isArray(aiResult.recommendations) || aiResult.recommendations.length === 0) {
            return res.status(502).json({ success: false, message: 'AI returned an invalid response' });
        }

        return res.json({ success: true, recommendations: aiResult.recommendations });

    } catch (error) {
        console.error('AI Career Recommend Error:', error);
        return res.status(500).json({ success: false, message: 'Server error during AI recommendation' });
    }
});

// ==========================
// 404 HANDLER
// ==========================
app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.method} ${req.url} not found on this server`
    });
});

// ==========================
// GLOBAL ERROR HANDLER
// ==========================
app.use((err, req, res, next) => {
    if (err && err.message === 'Not allowed by CORS') {
        return res.status(403).json({ success: false, message: 'Origin not allowed' });
    }
    console.error('Unhandled Error:', err);
    const payload = { success: false, message: 'Server error' };
    if (!isProduction && err) payload.error = err.message;
    res.status(500).json(payload);
});

// ==========================
// START SERVER
// ==========================
app.listen(PORT, () => {
        emailService.initEmailService();
        console.log(`🚀 Server running in ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'} mode on port ${PORT}`);
});
