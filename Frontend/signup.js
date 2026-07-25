/**
 * signup.js
 * Premium Auth Flow — Real-time validation, no alerts, password checklist
 */

document.addEventListener("DOMContentLoaded", () => {
    const signupForm = document.getElementById('signup-form');
    const nameInput = document.getElementById('signup-name');
    const emailInput = document.getElementById('signup-email');
    const passwordInput = document.getElementById('signup-password');
    const API_BASE = (window.XYVERRA_CONFIG?.API_BASE || 'http://localhost:5000');
    const confirmInput = document.getElementById('signup-confirm');
    const submitBtn = document.getElementById('signup-btn');
    const btnLabel = document.getElementById('btn-label');
    
    // OTP elements
    const otpForm = document.getElementById('otp-form');
    const otpCodeInput = document.getElementById('otp-code');
    const otpEmailDisplay = document.getElementById('otp-email-display');
    const btnVerifyOtp = document.getElementById('btn-verify-otp');
    const btnResendOtp = document.getElementById('btn-resend-otp');
    const otpError = document.getElementById('otp-error');
    
    // OTP State
    let resendTimer = null;
    let resendCooldown = 60; // seconds

    // Check for ?verify=1 redirect
    if (window.location.search.includes('verify=1')) {
        const storedEmail = localStorage.getItem('xyverra_user_email');
        const token = localStorage.getItem('token');
        if (storedEmail && token) {
            signupForm.style.display = 'none';
            otpForm.style.display = 'block';
            otpEmailDisplay.textContent = storedEmail;

            // Auto-send OTP on load
            fetch(`${API_BASE}/api/auth/send-otp`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            }).then(res => res.json()).then(data => {
                if (data.success || data.message?.includes('sent')) {
                    startResendTimer();
                }
            }).catch(e => console.warn('Auto OTP send failed:', e));
        }
    }

    // Toggles
    const togglePassword = document.getElementById('toggle-password');
    const toggleConfirm = document.getElementById('toggle-confirm');

    // Error elements
    const nameError = document.getElementById('name-error');
    const emailError = document.getElementById('email-error');
    const passwordError = document.getElementById('password-error');
    const confirmError = document.getElementById('confirm-error');
    
    const generalErrorCard = document.getElementById('general-error');
    const generalErrorText = document.getElementById('general-error-text');

    // Checklist elements
    const pwChecklist = document.getElementById('pw-checklist');
    const ruleLength = document.getElementById('rule-length');
    const ruleNumber = document.getElementById('rule-number');
    const ruleSpecial = document.getElementById('rule-special');

    // ── Toast Helper Removed (Using XyModal globally) ──
    const showFieldError = (input, errorDiv, message) => {
        input.classList.remove('input-field-success');
        input.classList.add('input-field-error');
        errorDiv.textContent = message;
        errorDiv.classList.add('visible');
    };

    const clearFieldError = (input, errorDiv) => {
        input.classList.remove('input-field-error');
        errorDiv.classList.remove('visible');
    };

    const setFieldSuccess = (input, errorDiv) => {
        clearFieldError(input, errorDiv);
        if (input.value.trim() !== '') {
            input.classList.add('input-field-success');
        } else {
            input.classList.remove('input-field-success');
        }
    };

    const showGeneralError = (message) => {
        window.XyError('Validation Error', message);
    };

    const hideGeneralError = () => {
        // No longer using inline general error
    };

    // ── Password Toggle ──
    const setupToggle = (btn, input) => {
        if (!btn || !input) return;
        btn.addEventListener('click', () => {
            const isText = input.type === 'text';
            input.type = isText ? 'password' : 'text';
            btn.className = isText ? 'far fa-eye eye-icon' : 'far fa-eye-slash eye-icon';
        });
    };
    setupToggle(togglePassword, passwordInput);
    setupToggle(toggleConfirm, confirmInput);

    // ── Validation State ──
    let state = {
        name: false,
        email: false,
        password: false,
        confirm: false
    };

    const checkFormReady = () => {
        if (state.name && state.email && state.password && state.confirm) {
            submitBtn.disabled = false;
        } else {
            submitBtn.disabled = true;
        }
    };

    // ── Real-time Input Listeners ──

    // Name
    nameInput.addEventListener('input', () => {
        hideGeneralError();
        if (nameInput.value.trim().length >= 2) {
            setFieldSuccess(nameInput, nameError);
            state.name = true;
        } else {
            clearFieldError(nameInput, nameError); // Don't show error while typing early
            nameInput.classList.remove('input-field-success');
            state.name = false;
        }
        checkFormReady();
    });

    nameInput.addEventListener('blur', () => {
        if (nameInput.value.trim() !== '' && nameInput.value.trim().length < 2) {
            showFieldError(nameInput, nameError, 'Name must be at least 2 characters');
        }
    });

    // Email
    emailInput.addEventListener('input', () => {
        hideGeneralError();
        clearFieldError(emailInput, emailError);
        emailInput.classList.remove('input-field-success');
        state.email = false;
        checkFormReady();
    });

    emailInput.addEventListener('blur', () => {
        const email = emailInput.value.trim();
        if (email === '') return;
        
        if (/\S+@\S+\.\S+/.test(email)) {
            setFieldSuccess(emailInput, emailError);
            state.email = true;
        } else {
            showFieldError(emailInput, emailError, 'Please enter a valid email address');
        }
        checkFormReady();
    });

    // Password
    passwordInput.addEventListener('input', () => {
        hideGeneralError();
        clearFieldError(passwordInput, passwordError);
        
        const pw = passwordInput.value;
        
        // Rules
        const isLength = pw.length >= 8;
        const hasNum = /\d/.test(pw);
        const hasSpec = /[!@#$%^&*(),.?":{}|<>]/.test(pw);

        // Update checklist UI
        if (isLength) ruleLength.classList.add('rule-pass'); else ruleLength.classList.remove('rule-pass');
        if (hasNum) ruleNumber.classList.add('rule-pass'); else ruleNumber.classList.remove('rule-pass');
        if (hasSpec) ruleSpecial.classList.add('rule-pass'); else ruleSpecial.classList.remove('rule-pass');

        if (isLength && hasNum && hasSpec) {
            pwChecklist.classList.add('all-valid');
            setFieldSuccess(passwordInput, passwordError);
            state.password = true;
        } else {
            pwChecklist.classList.remove('all-valid');
            passwordInput.classList.remove('input-field-success');
            state.password = false;
        }

        // Re-validate confirm password if it has value
        if (confirmInput.value !== '') {
            validateConfirm();
        }

        checkFormReady();
    });

    // Confirm Password
    const validateConfirm = () => {
        if (confirmInput.value === '') {
            state.confirm = false;
            return;
        }
        
        if (confirmInput.value === passwordInput.value) {
            setFieldSuccess(confirmInput, confirmError);
            state.confirm = true;
        } else {
            showFieldError(confirmInput, confirmError, 'Passwords do not match');
            state.confirm = false;
        }
    };

    confirmInput.addEventListener('input', () => {
        hideGeneralError();
        if (confirmInput.value !== '' && confirmInput.value === passwordInput.value) {
            setFieldSuccess(confirmInput, confirmError);
            state.confirm = true;
        } else {
            clearFieldError(confirmInput, confirmError);
            confirmInput.classList.remove('input-field-success');
            state.confirm = false;
        }
        checkFormReady();
    });

    confirmInput.addEventListener('blur', validateConfirm);


    // ── Form Submit ──
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Safety check
            if (!state.name || !state.email || !state.password || !state.confirm) {
                showGeneralError("Please complete all required fields correctly.");
                return;
            }

            // Gather Values
            const name = nameInput.value.trim();
            const email = emailInput.value.trim();
            const password = passwordInput.value;
            const skills = []; // Optional skills can go here if needed later

            // Loading state
            submitBtn.disabled = true;
            btnLabel.innerHTML = '<span class="btn-spinner"></span> Creating Account...';
            submitBtn.querySelector('i').style.display = 'none';

            try {
                const payload = { name, email, password, skills };
                const apiUrl = `${API_BASE}/api/auth/register`;

                const response = await fetch(apiUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await response.json();

                if (response.ok) {
                    // Success!
                    
                    // Clear previous user state
                    const keysToClear = ['xyverra_user_name', 'xyverra_user_email', 'xyverra_selected_path', 'userLevel', 'xyverra_selected_level', 'userSkills', 'xyverra_interests', 'completedModules', 'xyverra_skill_score', 'xyverra_user_streak', 'xyverra_xp', 'xyverra_onboarded', 'roadmapGenerated', 'completedCourses', 'quizResultLevel', 'quizResultScore', 'moduleQuizPassed'];
                    keysToClear.forEach(k => localStorage.removeItem(k));

                    // Save to localStorage
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('xyverra_user_name', data.user.name);
                    localStorage.setItem('xyverra_user_email', data.user.email);

                    if (data.message.includes("exists")) {
                        // If user somehow exists and is returned, just redirect them
                        const onboardingDone = data.user.onboardingCompleted || !!data.user.selectedPath || localStorage.getItem('xyverra_onboarded') === 'true';
                        window.location.href = onboardingDone ? 'dashboard.html' : 'career-discovery.html';
                    } else {
                        // Show OTP UI
                        signupForm.style.display = 'none';
                        otpForm.style.display = 'block';
                        otpEmailDisplay.textContent = email;
                        
                        // Automatically trigger sending OTP
                        try {
                            const otpResponse = await fetch(`${API_BASE}/api/auth/send-otp`, {
                                method: 'POST',
                                headers: { 
                                    'Content-Type': 'application/json',
                                    'Authorization': `Bearer ${data.token}`
                                }
                            });
                            const otpData = await otpResponse.json();
                            if (!otpResponse.ok) {
                                showFieldError(otpCodeInput, otpError, otpData.message || 'Failed to send OTP. Please click resend.');
                            } else {
                                window.XySuccess("Verification", "Verification code sent to your email!");
                                startResendTimer();
                                if (otpData._dev_otp) {
                                    setTimeout(() => {
                                        otpCodeInput.value = otpData._dev_otp;
                                        window.XySuccess("Demo Mode", "Code auto-filled because you are not using a custom domain");
                                    }, 1000);
                                }
                            }
                        } catch (err) {
                            showFieldError(otpCodeInput, otpError, 'Network error while sending OTP.');
                        }
                    }

                } else {
                    // Backend returned an error
                    if (data.message && data.message.toLowerCase().includes('exists')) {
                        showFieldError(emailInput, emailError, data.message);
                    } else {
                        showGeneralError(data.message || 'Registration failed. Please try again.');
                    }
                    
                    // Restore button
                    submitBtn.disabled = false;
                    btnLabel.innerHTML = 'Create Free Account';
                    submitBtn.querySelector('i').style.display = 'inline-block';
                }
            } catch (error) {
                console.error("Signup error details:", error);
                showGeneralError("Unable to connect to the server. Please check your connection.");
                
                // Restore button
                submitBtn.disabled = false;
                btnLabel.innerHTML = 'Create Free Account';
                submitBtn.querySelector('i').style.display = 'inline-block';
            }
        });
    }

    // Terms triggers
    document.getElementById('terms-link')?.addEventListener('click', () => window.XyInfo("Coming Soon", "Terms of Service page is under construction."));
    document.getElementById('privacy-link')?.addEventListener('click', () => window.XyInfo("Coming Soon", "Privacy Policy page is under construction."));

    // ── OTP Verification ──
    function startResendTimer() {
        if (resendTimer) clearInterval(resendTimer);
        resendCooldown = 60;
        if (!btnResendOtp) return;
        
        btnResendOtp.disabled = true;
        btnResendOtp.style.color = '#94a3b8';
        btnResendOtp.style.textDecoration = 'none';
        btnResendOtp.textContent = `Resend code (${resendCooldown}s)`;
        
        resendTimer = setInterval(() => {
            resendCooldown--;
            if (resendCooldown <= 0) {
                clearInterval(resendTimer);
                btnResendOtp.disabled = false;
                btnResendOtp.style.color = '#4F46E5';
                btnResendOtp.style.textDecoration = 'underline';
                btnResendOtp.textContent = 'Resend code';
            } else {
                btnResendOtp.textContent = `Resend code (${resendCooldown}s)`;
            }
        }, 1000);
    }

    if (otpForm) {
        otpForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const otpValue = otpCodeInput.value.trim();
            if (otpValue.length !== 6) {
                showFieldError(otpCodeInput, otpError, 'Please enter a 6-digit code');
                return;
            }

            btnVerifyOtp.disabled = true;
            btnVerifyOtp.innerHTML = '<span class="btn-spinner" style="margin-right: 8px;"></span> Verifying...';

            try {
                const token = localStorage.getItem('token');
                const response = await fetch(`${API_BASE}/api/auth/verify-otp`, {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                    },
                    body: JSON.stringify({ otp: otpValue })
                });

                const data = await response.json();

                if (response.ok) {
                    localStorage.setItem('xyverra_email_verified', 'true');
                    window.XySuccess("Account Verified", "Your account has been successfully verified! 🎉", () => {
                        window.location.href = 'career-discovery.html';
                    });
                } else {
                    showFieldError(otpCodeInput, otpError, data.message || 'Invalid verification code');
                    btnVerifyOtp.disabled = false;
                    btnVerifyOtp.innerHTML = '<i class="fas fa-check"></i> Verify Email';
                }
            } catch (error) {
                showFieldError(otpCodeInput, otpError, 'Network error while verifying OTP.');
                btnVerifyOtp.disabled = false;
                btnVerifyOtp.innerHTML = '<i class="fas fa-check"></i> Verify Email';
            }
        });

        if (btnResendOtp) {
            btnResendOtp.addEventListener('click', async () => {
                if (resendCooldown > 0 && resendCooldown < 60) return; // Prevent double click
                btnResendOtp.disabled = true;
                btnResendOtp.textContent = 'Resending...';
                try {
                    const token = localStorage.getItem('token');
                    const response = await fetch(`${API_BASE}/api/auth/send-otp`, {
                        method: 'POST',
                        headers: { 
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        }
                    });
                    const data = await response.json();
                    if (response.ok) {
                        window.XySuccess("Code Sent", "A new verification code has been sent.");
                        clearFieldError(otpCodeInput, otpError);
                        startResendTimer();
                        if (data._dev_otp) {
                            setTimeout(() => {
                                otpCodeInput.value = data._dev_otp;
                                window.XySuccess("Demo Mode", "Code auto-filled because you are not using a custom domain");
                            }, 1000);
                        }
                    } else {
                        showFieldError(otpCodeInput, otpError, data.message || 'Failed to resend code');
                        btnResendOtp.disabled = false;
                        btnResendOtp.textContent = 'Resend code';
                    }
                } catch (error) {
                    showFieldError(otpCodeInput, otpError, 'Network error while resending OTP.');
                    btnResendOtp.disabled = false;
                    btnResendOtp.textContent = 'Resend code';
                }
            });
        }
    }
});