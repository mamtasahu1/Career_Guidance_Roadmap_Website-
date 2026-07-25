# 📋 Backend Node.js Dependencies

This project uses **Node.js** (not Python), so there is no `requirements.txt`.
Dependencies are managed via `npm` and defined in `backend/package.json`.

## Runtime Dependencies

| Package              | Version   | Purpose                                        |
|----------------------|-----------|------------------------------------------------|
| express              | ^5.2.1    | Web server framework                           |
| mongoose             | ^9.6.3    | MongoDB object modeling (ODM)                  |
| mongodb              | ^7.2.0    | MongoDB Node.js driver                         |
| jsonwebtoken         | ^9.0.3    | JWT-based authentication                       |
| bcryptjs             | ^3.0.3    | Password hashing                               |
| dotenv               | ^17.4.2   | Load environment variables from .env           |
| nodemailer           | ^8.0.11   | Send OTP emails via Gmail SMTP                 |
| resend               | ^6.12.4   | Send emails via Resend API (fallback)          |
| helmet               | ^8.2.0    | HTTP security headers                          |
| cors                 | ^2.8.6    | Cross-Origin Resource Sharing middleware       |
| express-rate-limit   | ^8.5.2    | Rate limiting for API endpoints                |
| express-validator    | ^7.3.2    | Input validation and sanitization              |
| axios                | ^1.17.0   | HTTP client for external API calls             |
| node-cron            | ^4.5.0    | Scheduled background jobs                      |

## To install all dependencies

```bash
cd backend
npm install
```
