# Authentication & User Management App Documentation

## Overview
This full-stack application provides a secure authentication and user management system with real-time updates and admin analytics.
It allows users to register, verify email, log in, reset passwords, and manage their accounts securely.
It provides administrators with a dashboard to view user activity, revoke sessions, and monitor usage statistics.

## User Features
1. Account Creation
Users can sign up using a unique email and password.
Upon registration, an email verification link is sent.
Accounts remain inactive until verified.
2. Email Verification
Secure, tokenized verification link valid for a short time (e.g., 1 hour).
Prevents fraudulent or bot-created accounts.
3. Login / Logout
Secure login with hashed passwords and JWT authentication.
Session tokens stored in HTTP-only cookies (resistant to XSS).
Automatic logout after 10 minutes of inactivity.
4. Password Reset
Forgot password? Request an email link to reset it.
The reset token is time-limited and invalidated after use.
5. Account Deletion
Users can permanently delete their accounts.
Data removal is logged for admin analytics (deleted-user count).
6. Session Refresh
Seamless background token renewal using secure cookie-based refresh tokens.
Prevents session hijacking and token reuse attacks.

## Admin Features
1. Admin Dashboard
Lists all users with last login timestamps, verification status, and activity logs.
Filter and sort users by:
Name
Date range
Activity status
2. User Management
Admin can deactivate or permanently delete users.
Admin can revoke active refresh tokens (immediately invalidating sessions).
3. Analytics Graph
Displays real-time user activity using Socket.IO.
Shows login frequency, deletions over time, and active user counts.
4. Security Controls
Admin can view token metadata (last rotation time, IPs, etc.).
Restricted access—only admin users can access this section via JWT role claims.

## Security Architecture
| Feature                                 | Description                                                       |
| --------------------------------------- | ----------------------------------------------------------------- |
| **Password Hashing**                    | Uses bcrypt with salt to protect passwords in storage.            |
| **JWT Access Tokens**                   | Short-lived (~15 mins), used for user authentication.             |
| **Refresh Tokens**                      | Stored in secure, HTTP-only cookies. Rotated regularly.           |
| **CSRF Protection**                     | Enabled via same-site cookie policies and origin checks.          |
| **SQL Security**                        | All queries use parameterized statements to prevent injection.    |
| **Session Timeout**                     | Inactivity logout enforced via both backend and frontend timers.  |
| **Email Verification / Password Reset** | Secure one-time tokens stored hashed in DB with expiration.       |
| **HTTPS Enforcement**                   | Required in production for Secure cookies.                        |
| **Admin Access Control**                | Routes protected by JWT role-based middleware (`authorizeAdmin`). |


## Technologies Used
| Layer               | Technology                        | Purpose                                         |
| ------------------- | --------------------------------- | ----------------------------------------------- |
| **Frontend**        | Angular 15                        | UI framework for building reactive SPAs         |
|                     | RxJS                              | Async data streams and observables              |
|                     | Socket.IO Client                  | Real-time UI updates                            |
| **Backend**         | Node.js + Express                 | REST API, session logic, auth routes            |
|                     | Socket.IO                         | Real-time server push notifications             |
|                     | Nodemailer                        | Sending email verifications and password resets |
| **Database**        | MySQL                             | User storage, activity logs, token metadata     |
| **Auth**            | JWT + bcrypt                      | Authentication and password hashing             |
| **DevOps**          | GitHub Actions                    | CI pipeline for build/testing                   |
|                     | Shell Deploy Script               | Automated deployment setup                      |
| **Email Templates** | HTML templates with inline styles | Professional verification/reset emails          |


## System Flow
1. User registers → verification email sent
2. User verifies email → account activated
3. User logs in → JWT + refresh token issued
4. Inactivity (10 min) → logout
5. Admin views users and activity in dashboard
6. Real-time data via Socket.IO

## Flowchart
          ┌────────────────────┐
          │      Frontend      │
          │  (Angular + RxJS)  │
          └───────┬────────────┘
                  │
                  ▼
          ┌────────────────────┐
          │  Node.js + Express │
          │   (Auth + Admin)   │
          └───────┬────────────┘
                  │
     ┌────────────┼────────────┐
     ▼            ▼            ▼
     ┌────────┐   ┌────────┐   ┌───────────────┐
     │ MySQL  │   │ Email  │   │ Socket.IO     │
     │ Users, │   │ Server │   │ Real-time     │
     │ Tokens │   │ (SMTP) │   │ Notifications │
     └────────┘   └────────┘   └───────────────┘

## Deployment
Run the provided DEPLOY.sh script (or do manually):
```bash
# 1. Clone and configure
git clone <repo-url>
cd backend
cp .env.example .env  # fill in DB + SMTP info

# 2. Setup MySQL
mysql -u root -p < sql/schema.sql

# 3. Run backend
npm install
npm start

# 4. Run frontend
cd ../frontend
npm install
npm start
```

## Future Enhancements
- 2FA or authenticator app support
- Role-based permission system
- Audit logging for admin actions
- Email delivery monitoring dashboard
- PWA support for offline access

MIT License

Copyright (c) 2025 Alejandro Guillen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
