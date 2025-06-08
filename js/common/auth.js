// Global authentication state
let userIsAuthenticated = false;
let currentUser = null;
let userType = null; // 'admin' or 'client'

// Variable to track if the initial auth check is complete
let authCheckComplete = false;

// Function to check if user is authenticated
function isAuthenticated() {
    return userIsAuthenticated;
}

// Function to get current user type
function getUserType() {
    return userType;
}

// Function to update auth buttons in header
function updateAuthButtons() {
    const authButtonsContainer = document.getElementById('auth-buttons');
    if (!authButtonsContainer) return;

    if (userIsAuthenticated && currentUser) {
        // User is logged in
        let buttons = '';
        
        // Display minimal user info (email) for clients
        if (userType === 'client') {
            let userInfoHtml = '';
            console.log("auth.js: currentUser.picture for client:", currentUser.picture); // Debugging line
            if (currentUser.picture) {
                userInfoHtml += `<img src="${currentUser.picture}" alt="Profile" onerror="handleProfileImageError(this)" style="width: 30px; height: 30px; border-radius: 50%; vertical-align: middle; margin-right: 8px;">`;
            }
            userInfoHtml += `<span style="font-weight: bold;">${currentUser.name || currentUser.email}</span>`;
            buttons += `<span style="margin-right: 1rem;">${userInfoHtml}</span>`;
        } else if (userType === 'admin') {
            // For admins, display their name
            let userInfoHtml = '';
            console.log("auth.js: currentUser.picture for admin:", currentUser.picture); // Debugging line
            if (currentUser.picture) {
                userInfoHtml += `<img src="${currentUser.picture}" alt="Profile" onerror="handleProfileImageError(this)" style="width: 30px; height: 30px; border-radius: 50%; vertical-align: middle; margin-right: 8px;">`;
            }
            userInfoHtml += `<span style="margin-right: 1rem; font-weight: bold;">${currentUser.name || currentUser.email}</span>`;
            buttons += userInfoHtml;
        }
        
        // Add logout button
        buttons += `<button onclick="logout()" class="auth-button logout-button">Logout</button>`;
        
        authButtonsContainer.innerHTML = buttons;
    } else {
        // User is not logged in
        authButtonsContainer.innerHTML = `
            <a href="/auth/google" class="auth-button login-button">Login with Google</a>
        `;
    }
}

// New function to handle profile image loading errors
function handleProfileImageError(imgElement) {
    imgElement.onerror = null; // Prevent infinite loop if fallback also fails
    imgElement.outerHTML = '<span class="material-icons" style="vertical-align: middle; margin-right: 8px;">account_circle</span>';
}

// Function to handle login
async function handleLogin(userData) {
    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData)
        });

        if (!response.ok) {
            throw new Error('Login failed');
        }

        const data = await response.json();
        userIsAuthenticated = true;
        currentUser = data.user;
        userType = data.userType; // 'admin' or 'client'
        
        // Update UI
        updateAuthButtons();
        
        // Show success message
        const authStatus = document.getElementById('auth-status');
        if (authStatus) {
            authStatus.style.display = 'block';
            authStatus.innerHTML = `<p>Welcome, ${currentUser.name || currentUser.email}!</p>`;
            setTimeout(() => {
                authStatus.style.display = 'none';
            }, 3000);
        }

        // Redirect to appropriate dashboard
        if (userType === 'admin') {
            window.location.href = 'admin-dashboard.html';
        } else {
            window.location.href = 'my-requests.html';
        }
    } catch (error) {
        console.error('Login error:', error);
        const authStatus = document.getElementById('auth-status');
        if (authStatus) {
            authStatus.style.display = 'block';
            authStatus.innerHTML = `<p style="color: red;">Login failed: ${error.message}</p>`;
        }
    }
}

// Function to handle logout
async function logout() {
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST'
        });

        if (!response.ok) {
            throw new Error('Logout failed');
        }

        // Reset auth state
        userIsAuthenticated = false;
        currentUser = null;
        userType = null;
        
        // Update UI
        updateAuthButtons();
        
        // Show logout message
        const authStatus = document.getElementById('auth-status');
        if (authStatus) {
            authStatus.style.display = 'block';
            authStatus.innerHTML = '<p>You have been logged out successfully.</p>';
            setTimeout(() => {
                authStatus.style.display = 'none';
            }, 3000);
        }

        // Redirect to home page
        window.location.href = 'index.html';
    } catch (error) {
        console.error('Logout error:', error);
        const authStatus = document.getElementById('auth-status');
        if (authStatus) {
            authStatus.style.display = 'block';
            authStatus.innerHTML = '<p style="color: red;">Logout failed. Please try again.</p>';
        }
    }
}

// Check authentication status on page load
async function checkAuthStatus() {
    try {
        const response = await fetch('/api/auth/status');
        if (!response.ok) {
            // Even if not OK, we process the response to get authenticated status
             // This is important if the server sends { authenticated: false } with a non-200 status
             // but the current backend sends 200 with { authenticated: false }
            console.warn('Auth status fetch non-OK response:', response.status);
             // Attempt to parse JSON anyway
            const data = await response.json().catch(() => ({ authenticated: false }));
             userIsAuthenticated = data.authenticated;
             currentUser = data.user || null;
             userType = data.userType || null;

             if (!response.ok) {
                 // If response was not OK, still throw an error after processing status
                 throw new Error(`Auth status fetch failed with status: ${response.status}`);
             }

             return data; // Return data on success

        }

        const data = await response.json();
        userIsAuthenticated = data.authenticated;
        currentUser = data.user;
        userType = data.userType;

        console.log('Auth status checked:', userIsAuthenticated, userType);

        return data; // Return the data

    } catch (error) {
        console.error('Auth status check error:', error);
        userIsAuthenticated = false;
        currentUser = null;
        userType = null;
        // Do NOT re-throw the error, just log it. The page should still try to render.
        return { authenticated: false }; // Return a default unauthenticated state on error
    } finally {
        authCheckComplete = true; // Mark check as complete
        // Dispatch a custom event to signal that auth check is complete
        const event = new CustomEvent('authCheckComplete', { detail: { isAuthenticated: userIsAuthenticated, userType: userType } });
        document.dispatchEvent(event);
    }
}

// Function to wait for the initial auth check to complete
function waitForAuthCheck() {
    return new Promise(resolve => {
        if (authCheckComplete) {
            resolve({ isAuthenticated: userIsAuthenticated, userType: userType });
        } else {
            document.addEventListener('authCheckComplete', (event) => {
                resolve(event.detail);
            });
        }
    });
}

// Initialize auth status when page loads
document.addEventListener('DOMContentLoaded', async () => {
    console.log("auth.js DOMContentLoaded: Starting initial auth check...");
    await checkAuthStatus(); // Await the initial check
    console.log("auth.js DOMContentLoaded: Initial auth check complete, userIsAuthenticated:", userIsAuthenticated, "userType:", userType);
    updateAuthButtons(); // Update buttons after status is known
});

// Export functions and the waiting promise for use in other scripts
window.isAuthenticated = isAuthenticated;
window.getUserType = getUserType;
window.logout = logout;
window.handleLogin = handleLogin;
window.waitForAuthCheck = waitForAuthCheck; // Export the new function