<p align="center">
  <img src="Frontend/xyverra_logo.jpeg" alt="Xyverra Logo" width="120" />
</p>

<h1 align="center">Xyverra — AI-Powered Career Guidance Platform</h1>

<p align="center">
  <strong>Personalized roadmaps · AI counselor · Interview prep · Skill gap analysis</strong>
  <br/>
  <a href="https://career-guidance-roadmap-website.vercel.app">🌐 Live Demo</a> ·
  <a href="#-quick-start">Quick Start</a> ·
  <a href="#-deployment">Deployment</a> ·
  <a href="#-environment-variables">Environment Variables</a>
</p>

---

## 📌 About the Project

Xyverra is a full-stack career guidance web application that helps users discover their ideal career path, build personalised learning roadmaps, and prepare for job interviews — all powered by AI.

**Key Features:**
- 🤖 **AI Career Counselor** — Real-time chat powered by Groq LLM
- 🗺️ **Personalised Roadmaps** — Step-by-step learning paths for 15+ career tracks
- 🎯 **Skill Gap Analysis** — Know exactly what skills you are missing
- 📝 **Interview Prep** — AI-generated questions with scoring feedback
- 📊 **Career Analytics** — Track your learning progress visually
- 🔐 **Secure Auth** — JWT + OTP email verification
- 👑 **Admin Panel** — Manage users, view analytics, send notifications

---

## 🛠️ Tech Stack

| Layer     | Technology                        |
|-----------|-----------------------------------|
| Frontend  | HTML5, Vanilla CSS, Vanilla JS    |
| Backend   | Node.js, Express.js               |
| Database  | MongoDB Atlas (Mongoose ODM)      |
| AI        | Groq API (LLaMA 3)                |
| Email     | Gmail SMTP / Resend API           |
| Auth      | JWT + bcrypt + OTP email verify   |
| Hosting   | Vercel (Frontend) + Render (Backend) |

---

## 🚀 Quick Start (Local Development)

### Prerequisites
- [Node.js](https://nodejs.org/) v18 or higher
- [MongoDB Atlas](https://cloud.mongodb.com) free account (or local MongoDB)
- [Groq API Key](https://console.groq.com) (free)
- [Git](https://git-scm.com/)

### 1. Clone the repository

```bash
git clone https://github.com/mamtasahu1/Career_Guidance_Roadmap_Website-.git
cd Career_Guidance_Roadmap_Website-
```

### 2. Set up the backend

```bash
cd backend
npm install
cp .env.example .env
```

Now open `backend/.env` and fill in all the required values (see [Environment Variables](#-environment-variables) below).

### 3. Start the backend server

```bash
npm start
# Server will start on http://localhost:5000
```

### 4. Open the frontend

Open `Frontend/index.html` directly in your browser, **or** use a local server extension like [Live Server](https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer) in VS Code.

> ⚠️ Make sure `Frontend/config.js` has `API_BASE: 'http://localhost:5000'` for local development.

---

## 🌐 Deployment

The project is pre-configured for deployment on **Vercel** (Frontend) and **Render** (Backend).

### Frontend → Vercel

1. Push this repository to GitHub.
2. Go to [vercel.com](https://vercel.com) → New Project → Import your repo.
3. Set **Root Directory** to `Frontend`.
4. Click **Deploy**. ✅

### Backend → Render

1. Go to [render.com](https://render.com) → New Web Service → Connect your repo.
2. Set **Root Directory** to `backend`.
3. Set **Build Command** to `npm install`.
4. Set **Start Command** to `node server.js`.
5. Add all [Environment Variables](#-environment-variables) in the Render dashboard.
6. Click **Deploy**. ✅

### After both are deployed:

1. Update `Frontend/config.js`:
   ```js
   API_BASE: 'https://your-backend.onrender.com'
   ```
2. Update Render env vars:
   ```
   ALLOWED_ORIGINS = https://your-site.vercel.app
   FRONTEND_URL    = https://your-site.vercel.app
   ```
3. Push changes → Vercel auto-redeploys.

---

## 🔑 Environment Variables

Copy `backend/.env.example` to `backend/.env` and fill in the values:

| Variable          | Required | Description                                             |
|-------------------|----------|---------------------------------------------------------|
| `MONGO_URI`       | ✅ Yes   | MongoDB Atlas connection string                         |
| `JWT_SECRET`      | ✅ Yes   | Random secret for signing tokens (32+ chars)            |
| `JWT_EXPIRES_IN`  | No       | Token expiry duration (default: `24h`)                  |
| `PORT`            | No       | Server port (default: `5000`)                           |
| `NODE_ENV`        | No       | `development` or `production`                           |
| `SMTP_HOST`       | No       | Email SMTP host (default: `smtp.gmail.com`)             |
| `SMTP_PORT`       | No       | Email SMTP port (default: `587`)                        |
| `SMTP_SECURE`     | No       | Use TLS? `true` or `false` (default: `false`)           |
| `SMTP_USER`       | No*      | Your Gmail address                                      |
| `SMTP_PASS`       | No*      | Gmail [App Password](https://myaccount.google.com/apppasswords) (16 chars) |
| `EMAIL_FROM`      | No       | Display name for sent emails                            |
| `EMAIL_API_KEY`   | No*      | [Resend](https://resend.com) API key (recommended for production) |
| `GROQ_API_KEY`    | ✅ Yes   | [Groq](https://console.groq.com) API key for AI features |
| `ALLOWED_ORIGINS` | No       | Comma-separated list of allowed frontend URLs (CORS)    |
| `FRONTEND_URL`    | No       | Your deployed frontend URL                              |

> \* At least one email provider (`SMTP_PASS` **or** `EMAIL_API_KEY`) must be set for OTP email verification to work.

---

## 📁 Project Structure

```
Career_Guidance_Roadmap_Website-/
│
├── Frontend/                  # Static frontend (HTML/CSS/JS)
│   ├── index.html             # Entry point (homepage)
│   ├── config.js              # ← Set your API_BASE URL here
│   ├── global.css             # Global styles
│   ├── dashboard.html/js      # User dashboard
│   ├── roadmap.html/js        # Career roadmap viewer
│   ├── counselor.html/js      # AI career counselor chat
│   ├── interview-prep.html/js # AI interview practice
│   ├── skill-gap.html/js      # Skill gap analysis
│   ├── admin.html/js          # Admin panel
│   └── ...                    # Other pages
│
├── backend/                   # Node.js / Express API server
│   ├── server.js              # Main server entry point (all routes)
│   ├── models/                # Mongoose data models
│   ├── routes/                # Express route files
│   ├── middleware/            # Auth & other middleware
│   ├── services/              # Business logic services
│   ├── utils/                 # Helper utilities
│   ├── .env.example           # Environment variable template
│   └── package.json           # Node.js dependencies
│
├── requirements.md            # Dependency reference (for contributors)
└── README.md                  # This file
```

---

## 👥 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

---

## 🙏 Acknowledgements

- [Groq](https://groq.com) — Lightning-fast AI inference
- [MongoDB Atlas](https://cloud.mongodb.com) — Free cloud database
- [Vercel](https://vercel.com) — Frontend hosting
- [Render](https://render.com) — Backend hosting
- [Resend](https://resend.com) — Transactional email API
