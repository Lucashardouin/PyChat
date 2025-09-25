// Update current time
function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    const timeElement = document.getElementById('currentTime');
    if (timeElement) {
        timeElement.textContent = `${timeString} PST`;
    }
}

updateTime();
setInterval(updateTime, 1000);

// Initial system messages to display on startup
const initialMessages = [
    { sender: 'SYSTEM', content: 'Network initialized. Welcome to the wasteland communication grid.', delay: 100 },
    { sender: 'SYSTEM', content: 'Connection established to Champs-sur-Marne relay station.', delay: 2000 },
    { sender: 'SYSTEM', content: 'Warning: Unknown AI signatures detected on network perimeter.', delay: 4000 },
    { sender: 'SYSTEM', content: 'Firewall protocols activated. Deep packet inspection enabled.', delay: 6000 },
    { sender: 'SYSTEM', content: 'Security protocol engaged. All transmissions are monitored.', delay: 8000 },
    { sender: 'SYSTEM', content: 'Encryption keys synchronized with Île-de-France network nodes.', delay: 10000 },
    { sender: 'SYSTEM', content: 'AI threat detection algorithms loaded and running.', delay: 12000 },
    { sender: 'SYSTEM', content: 'Network stability: NOMINAL. Latency: 45ms to primary server.', delay: 14000 },
    { sender: 'SYSTEM', content: 'Authentication required to participate in network communications.', delay: 16000 }
];

// Display initial messages with delays
function displayInitialMessages() {
    initialMessages.forEach((msg, index) => {
        setTimeout(() => {
            addMessage(msg.sender, msg.content);
        }, msg.delay);
    });
}

// Add message function
function addMessage(sender, content) {
    const messagesContainer = document.getElementById('messagesContainer');
    if (!messagesContainer) return;

    const messageDiv = document.createElement('div');
    messageDiv.className = 'message';

    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });

    messageDiv.innerHTML = `
        <div class="message-meta">[${sender}] - ${timeString}</div>
        <div class="message-content">${content}</div>
    `;

    messagesContainer.appendChild(messageDiv);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

// Random system messages for atmosphere
const systemMessages = [
    'Network scan complete. Multiple nodes active.',
    'AI signature analysis in progress.',
    'Communication array recalibrated.',
    'Warning: Unknown AI signatures detected.',
    'Ultron threat protocols activated.',
    'Security sweep initiated.',
    'Network encryption updated.',
    'Authentication server responding normally.'
];

// Start displaying messages when page loads
document.addEventListener('DOMContentLoaded', function() {
    displayInitialMessages();

    // Random system messages (only after initial sequence)
    setTimeout(() => {
        setInterval(() => {
            if (Math.random() > 0.7) {
                const randomMessage = systemMessages[Math.floor(Math.random() * systemMessages.length)];
                addMessage('SYSTEM', randomMessage);
            }
        }, 15000);
    }, 17000);

    // Login functionality
    const loginForm = document.getElementById('loginForm');
    const basecampForm = document.getElementById('basecampForm');
    const logoutBtn = document.getElementById('logoutBtn');

    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            if (username && password) {
                // Send login request to server
                fetch('/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: username,
                        password: password
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Hide login form, show basecamp form
                        document.getElementById('loginPanel').style.transform = 'translateY(-20px)';
                        document.getElementById('loginPanel').style.opacity = '0.7';

                        setTimeout(() => {
                            loginForm.style.display = 'none';
                            document.getElementById('basecampPanel').style.display = 'block';
                            document.getElementById('loginPanel').style.transform = 'translateY(0)';
                            document.getElementById('loginPanel').style.opacity = '1';
                        }, 500);

                        addMessage('SYSTEM', data.message);
                    } else {
                        addMessage('SYSTEM', `ERROR: ${data.message}`);
                        // Clear password field
                        document.getElementById('password').value = '';
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    addMessage('SYSTEM', 'ERROR: Network communication failure');
                });
            }
        });
    }

    if (basecampForm) {
        basecampForm.addEventListener('submit', function(e) {
            e.preventDefault();

            const basecampCode = document.getElementById('basecampCode').value;

            if (basecampCode) {
                // Send basecamp verification request
                fetch('/verify_basecamp', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        basecamp_code: basecampCode
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        addMessage('SYSTEM', data.message);
                        // Redirect to basecamp
                        setTimeout(() => {
                            window.location.href = '/basecamp';
                        }, 1000);
                    } else {
                        addMessage('SYSTEM', `ERROR: ${data.message}`);
                        // Clear basecamp code field
                        document.getElementById('basecampCode').value = '';
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                    addMessage('SYSTEM', 'ERROR: Network communication failure');
                });
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', function() {
            fetch('/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => response.json())
            .then(data => {
                addMessage('SYSTEM', data.message);
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            })
            .catch(error => {
                console.error('Error:', error);
                window.location.reload();
            });
        });
    }
});

