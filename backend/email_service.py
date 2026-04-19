"""
email_service.py — SMTP Email Service for RogueShield
Handles password reset and notification emails.
"""
import os
import smtplib
import ssl
import secrets
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "rogueapshield@gmail.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "jtqiatvkbaaiogjk")
FROM_NAME = "RogueShield"

def send_email(to: str, subject: str, html_body: str, text_body: str = "") -> bool:
    """
    Send an email via SMTP.
    Returns True on success, False on failure.
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{FROM_NAME} <{SMTP_USER}>"
        msg["To"] = to

        msg.attach(MIMEText(text_body or html_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to, msg.as_string())
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False

def generate_reset_token() -> str:
    """Generate a secure reset token."""
    return secrets.token_urlsafe(32)

def send_password_reset_email(to_email: str, username: str, reset_link: str) -> bool:
    """Send password reset email with HTML template."""
    subject = "RogueShield - Password Reset Request"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: 'Inter', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #0066ff, #00c8ff); padding: 30px; text-align: center; }}
            .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; }}
            .content {{ padding: 40px 30px; }}
            .content h2 {{ color: #333333; margin-top: 0; }}
            .content p {{ color: #666666; line-height: 1.6; }}
            .button {{ display: inline-block; background: linear-gradient(135deg, #00c8ff, #0066ff); color: #ffffff !important; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 20px 0; }}
            .button:hover {{ opacity: 0.9; }}
            .warning {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 20px 0; }}
            .footer {{ background: #f8f9fa; padding: 20px 30px; text-align: center; color: #999999; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ RogueShield</h1>
            </div>
            <div class="content">
                <h2>Password Reset Request</h2>
                <p>Hello {username},</p>
                <p>We received a request to reset your RogueShield account password. Click the button below to create a new password:</p>
                <p style="text-align: center;">
                    <a href="{reset_link}" class="button">Reset Password</a>
                </p>
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong><br>
                    • This link expires in 1 hour<br>
                    • If you didn't request this, please ignore this email<br>
                    • Never share this link with anyone
                </div>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #0066ff;">{reset_link}</p>
            </div>
            <div class="footer">
                <p>RogueShield — Rogue Access Point Detection System<br>
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
RogueShield - Password Reset Request

Hello {username},

We received a request to reset your RogueShield account password.

Click the link below to reset your password:
{reset_link}

This link expires in 1 hour.
If you didn't request this, please ignore this email.

---
RogueShield - Rogue Access Point Detection System

    """
    
    return send_email(to_email, subject, html, text)

def send_welcome_email(to_email: str, username: str) -> bool:
    """Send welcome email to new users."""
    subject = "Welcome to RogueShield"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: 'Inter', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #0066ff, #00c8ff); padding: 30px; text-align: center; }}
            .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; }}
            .content {{ padding: 40px 30px; }}
            .content h2 {{ color: #333333; margin-top: 0; }}
            .content p {{ color: #666666; line-height: 1.6; }}
            .footer {{ background: #f8f9fa; padding: 20px 30px; text-align: center; color: #999999; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ RogueShield</h1>
            </div>
            <div class="content">
                <h2>Welcome, {username}!</h2>
                <p>Your RogueShield account has been successfully created.</p>
                <p>You can now:</p>
                <ul>
                    <li>Analyze wireless capture files for rogue APs</li>
                    <li>Manage your authorised BSSID whitelist</li>
                    <li>Generate detailed PDF reports</li>
                </ul>
                <p>Contact your system administrator if you need assistance.</p>
            </div>
            <div class="footer">
                <p>RogueShield — Rogue Access Point Detection System<br>
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return send_email(to_email, subject, html)

def send_2fa_code(to_email: str, username: str, code: str) -> bool:
    """Send 2FA verification code email."""
    subject = "RogueShield - Your Verification Code"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: 'Inter', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #0066ff, #00c8ff); padding: 30px; text-align: center; }}
            .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; }}
            .content {{ padding: 40px 30px; text-align: center; }}
            .content h2 {{ color: #333333; margin-top: 0; font-size: 18px; }}
            .content p {{ color: #666666; line-height: 1.6; margin-bottom: 20px; }}
            .code-box {{ background: linear-gradient(135deg, #0066ff, #00c8ff); padding: 30px 40px; border-radius: 12px; margin: 30px auto; display: inline-block; }}
            .code {{ font-size: 36px; font-weight: 700; color: #ffffff; letter-spacing: 8px; font-family: 'Courier New', monospace; }}
            .warning {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 20px 0; text-align: left; }}
            .warning strong {{ color: #856404; }}
            .footer {{ background: #f8f9fa; padding: 20px 30px; text-align: center; color: #999999; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>RogueShield</h1>
            </div>
            <div class="content">
                <h2>Your Verification Code</h2>
                <p>Hello <strong>{username}</strong>,</p>
                <p>Here is your verification code for logging into RogueShield:</p>
                <div class="code-box">
                    <span class="code">{code}</span>
                </div>
                <p style="font-size: 14px; color: #888;">This code expires in <strong>10 minutes</strong>.</p>
                <div class="warning">
                    <strong>Security Notice:</strong><br>
                    If you did not attempt to log in, someone may be trying to access your account. Please ignore this email and consider changing your password.
                </div>
            </div>
            <div class="footer">
                <p>RogueShield — Rogue Access Point Detection System<br>
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
RogueShield - Your Verification Code

Hello {username},

Here is your verification code for logging into RogueShield:

{code}

This code expires in 10 minutes.

If you did not attempt to log in, someone may be trying to access your account. Please ignore this email and consider changing your password.

---
RogueShield — Rogue Access Point Detection System

    """
    
    return send_email(to_email, subject, html, text)

def send_account_approved_email(to_email: str, username: str) -> bool:
    """Send account approval notification email to newly approved users."""
    subject = "RogueShield - Your Account Has Been Approved"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: 'Inter', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #0066ff, #00c8ff); padding: 30px; text-align: center; }}
            .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; }}
            .content {{ padding: 40px 30px; }}
            .content h2 {{ color: #333333; margin-top: 0; }}
            .content p {{ color: #666666; line-height: 1.6; }}
            .success-box {{ background: #d4edda; border: 1px solid #28a745; border-radius: 8px; padding: 20px; margin: 20px 0; text-align: center; }}
            .success-icon {{ font-size: 48px; margin-bottom: 10px; }}
            .success-text {{ color: #155724; font-size: 18px; font-weight: 600; }}
            .footer {{ background: #f8f9fa; padding: 20px 30px; text-align: center; color: #999999; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>RogueShield</h1>
            </div>
            <div class="content">
                <h2>Account Approved!</h2>
                <p>Hello <strong>{username}</strong>,</p>
                <p>Great news! Your RogueShield account has been approved by the administrator.</p>
                <div class="success-box">
                    <div class="success-icon">✓</div>
                    <div class="success-text">Your account is now active!</div>
                </div>
                <p>You can now log in to RogueShield with your credentials and start using the system.</p>
                <p>If you have any questions, please contact your system administrator.</p>
            </div>
            <div class="footer">
                <p>RogueShield — Rogue Access Point Detection System<br>
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
RogueShield - Account Approved!

Hello {username},

Great news! Your RogueShield account has been approved by the administrator.

You can now log in to RogueShield with your credentials and start using the system.

If you have any questions, please contact your system administrator.

---
RogueShield — Rogue Access Point Detection System
    """
    
    return send_email(to_email, subject, html, text)

def send_registration_received_email(to_email: str, username: str) -> bool:
    """Send email confirming registration is pending admin approval."""
    subject = "RogueShield - Registration Received"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: 'Inter', Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #f39c12, #e67e22); padding: 30px; text-align: center; }}
            .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; }}
            .content {{ padding: 40px 30px; }}
            .content h2 {{ color: #333333; margin-top: 0; }}
            .content p {{ color: #666666; line-height: 1.6; }}
            .info-box {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 20px; margin: 20px 0; }}
            .info-icon {{ font-size: 48px; margin-bottom: 10px; text-align: center; }}
            .footer {{ background: #f8f9fa; padding: 20px 30px; text-align: center; color: #999999; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>RogueShield</h1>
            </div>
            <div class="content">
                <h2>Registration Received</h2>
                <p>Hello <strong>{username}</strong>,</p>
                <p>Thank you for registering with RogueShield!</p>
                <div class="info-box">
                    <div class="info-icon">⏳</div>
                    <p style="margin:0; text-align:center;"><strong>Your account is pending approval.</strong></p>
                    <p style="margin:10px 0 0 0; text-align:center; color:#856404;">An administrator will review your registration and approve your account. You will receive an email once your account is activated.</p>
                </div>
                <p>You will be able to log in once your account has been approved.</p>
                <p>If you have any questions, please contact your system administrator.</p>
            </div>
            <div class="footer">
                <p>RogueShield — Rogue Access Point Detection System<br>
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text = f"""
RogueShield - Registration Received

Hello {username},

Thank you for registering with RogueShield!

Your account is pending approval. An administrator will review your registration and approve your account. You will receive an email once your account is activated.

You will be able to log in once your account has been approved.

If you have any questions, please contact your system administrator.

---
RogueShield — Rogue Access Point Detection System
    """
    
    return send_email(to_email, subject, html, text)
