# Twitter Clone App

## Description

A Django-based social media platform inspired by Twitter, featuring user authentication, messaging, avatars, and
two-factor authentication (2FA).

## Features

- **User Registration & Login**: Sign up with a username, email, and password. Login with 2FA support.
- **Posting Messages**: Users can post text messages with optional images and markdown formatting.
- **User Profiles**: View and update user profiles, including uploading avatars.
- **Message Deletion**: Delete messages posted by the user.
- **Device Management**: Track user devices and manage login sessions.
- **Password Reset**: Forgot password feature with 2FA verification.
- **Two-Factor Authentication (2FA)**: Secure login with TOTP-based 2FA.

## Installation

### Prerequisites

#### To run the application, you need the following software installed on your system:

1. Docker
2. Python3
3. pip

### Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/amdla/OchronaDanychProj
   ```

2. **Modify the `.env` file in `twitter_app` directory with your keys**

   ```env
   SECRET_KEY=your_secret_key
   TOTP_ENCRYPTION_KEY=your_totp_encryption_key
   ```
   #### Bear in mind that both keys will allow you to use the data created just with these keys. If you lose them, you will lose access to the data. The same way - you can't access the data created with different keys.

3. **Prevent from accidentally pushing your `.env` file to the repository**

   ```bash
   git update-index --assume-unchanged twitter_app/.env
   ```
4. **Install the Required Python Packages**

   ```bash
   pip install -r requirements.txt
   ```

5. **Build and Run the Docker Containers**

   ```bash
   docker compose up --build
   ```
6. **Access the Application**

   Open your browser and navigate to `https://localhost/`.

## Usage

### User Registration and Login

- Register a new user by filling out the registration form.
- Log in using your username and password.
- Follow the setup instructions to configure 2FA.

### Posting Messages

- On the homepage, use the form to post text messages with optional image uploads.

### Managing Profiles

- Navigate to your profile to upload or change your avatar.

### Device Management

- View and manage devices associated with your account.

### Password Reset

- Use the "Forgot Password" feature to reset your password securely.

### 2FA Setup and Verification

- Enable/Disable 2FA via the profile settings.
- Use an authenticator app to scan the QR code and enter the TOTP.

## Technical Details

### Project Structure

- `settings.py`: Configurations for the Django project.
- `urls.py`: URL routing for the application.
- `utils.py`: Utility functions including password hashing and validation.
- `views.py`: Business logic for handling requests and rendering templates.
- `forms.py`: Form definitions for user input validation.
- `models.py`: Database models for users, messages, and devices.
- `wsgi.py`: WSGI application entry point.
