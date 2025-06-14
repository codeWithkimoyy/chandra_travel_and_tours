// Check if user is admin
document.addEventListener('DOMContentLoaded', async () => {
    try {
        // First check if user is authenticated
        const authResponse = await fetch('/api/auth/status');
        const authData = await authResponse.json();
        
        if (!authData.authenticated) {
            console.log('User not authenticated, redirecting to login');
            window.location.href = '/index.html';
            return;
        }

        // Then check if user is admin
        const adminResponse = await fetch('/api/check-admin');
        const adminData = await adminResponse.json();
        
        if (!adminData.isAdmin) {
            console.log('User is not an admin, redirecting to home');
            window.location.href = '/index.html';
            return;
        }

        // If we get here, user is authenticated and is an admin
        console.log('Admin access granted');
        initializeDashboard();
    } catch (error) {
        console.error('Error checking admin status:', error);
        window.location.href = '/index.html';
    }
});

// Initialize dashboard
async function initializeDashboard() {
    console.log('Initializing dashboard...');
    await Promise.all([
        loadStatistics(),
        loadCharts(),
        loadRequests()
    ]);
    setupEventListeners();
}

// Load dashboard statistics
async function loadStatistics() {
    try {
        const response = await fetch('/api/admin/stats');
        const stats = await response.json();
        
        // Update stat cards
        document.getElementById('total-requests').textContent = stats.totalRequests;
        document.getElementById('pending-requests').textContent = stats.pendingRequests;
        document.getElementById('completed-today').textContent = stats.completedToday;
        document.getElementById('active-users').textContent = stats.activeUsers;

        // Update trends
        updateTrend('total-trend', stats.totalTrend);
        updateTrend('pending-trend', stats.pendingTrend);
        updateTrend('completed-trend', stats.completedTrend);
        updateTrend('users-trend', stats.usersTrend);
    } catch (error) {
        console.error('Error loading statistics:', error);
        showNotification('Error loading statistics', 'error');
    }
}

// Update trend indicator
function updateTrend(elementId, trend) {
    const element = document.getElementById(elementId);
    if (trend > 0) {
        element.innerHTML = `<span class="material-icons trend-up">trending_up</span> ${trend}%`;
        element.className = 'trend trend-up';
    } else if (trend < 0) {
        element.innerHTML = `<span class="material-icons trend-down">trending_down</span> ${Math.abs(trend)}%`;
        element.className = 'trend trend-down';
    } else {
        element.innerHTML = '<span class="material-icons">trending_flat</span> 0%';
        element.className = 'trend';
    }
}

// Load and initialize charts
async function loadCharts() {
    try {
        const response = await fetch('/api/admin/chart-data');
        const data = await response.json();
        
        // Request Trends Chart
        new Chart(document.getElementById('trendsChart'), {
            type: 'line',
            data: {
                labels: data.trends.labels,
                datasets: data.trends.datasets.map(dataset => ({
                    ...dataset,
                    borderColor: getRandomColor(), // Assign a random color
                    backgroundColor: getRandomColor(0.2), // Assign a random color with transparency for fill
                    pointBackgroundColor: getRandomColor(),
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: getRandomColor()
                }))
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'bottom',
                        labels: {
                            font: { size: 14 }
                        }
                    },
                    title: {
                        display: true,
                        text: 'Requests by Service Type Over Time',
                        font: { size: 20 },
                        padding: { top: 20, bottom: 20 }
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                        callbacks: {
                            title: function(tooltipItems) {
                                return `Date: ${tooltipItems[0].label}`;
                            },
                            label: function(tooltipItem) {
                                const serviceType = tooltipItem.dataset.label;
                                const count = tooltipItem.parsed.y;
                                return `${serviceType}: ${count}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Date'
                        }
                    },
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Number of Requests'
                        },
                        ticks: {
                            stepSize: 1,
                            precision: 0
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error loading charts:', error);
        showNotification('Error loading charts', 'error');
    }
}

// Helper function to generate a random color for chart lines
function getRandomColor(alpha = 1) {
    const r = Math.floor(Math.random() * 255);
    const g = Math.floor(Math.random() * 255);
    const b = Math.floor(Math.random() * 255);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

// Load requests with filtering
async function loadRequests() {
    console.log('Attempting to load requests...');
    const statusFilter = document.getElementById('status-filter').value;
    const serviceFilter = document.getElementById('service-filter').value;
    const dateFrom = document.getElementById('date-from').value;
    const dateTo = document.getElementById('date-to').value;
    const searchQuery = document.getElementById('search-filter').value;

    try {
        const queryParams = new URLSearchParams({
            status: statusFilter,
            service: serviceFilter,
            dateFrom,
            dateTo,
            search: searchQuery
        });

        console.log('Fetching requests with query params:', queryParams.toString());
        const response = await fetch(`/api/admin/requests?${queryParams}`);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Network response was not ok:', response.status, errorText);
            throw new Error(`HTTP error! status: ${response.status} - ${errorText}`);
        }

        const requests = await response.json();
        console.log('Received requests data:', requests);
        
        const tableBody = document.getElementById('requests-table-body');
        tableBody.innerHTML = '';

        const noRequestsMessage = document.getElementById('no-requests-message');

        if (requests.length === 0) {
            noRequestsMessage.style.display = 'flex';
            return;
        } else {
            noRequestsMessage.style.display = 'none';
        }
        
        requests.forEach(request => {
            const row = tableBody.insertRow();
            row.innerHTML = `
                <td>${request._id}</td>
                <td>${request.clientName}</td>
                <td>${request.serviceType}</td>
                <td>${new Date(request.submissionDate).toLocaleDateString()}</td>
                <td><span class="status-badge status-${request.status.toLowerCase().replace(/ /g, '-') || 'unknown'}">${request.status || 'Unknown'}</span></td>
                <td>
                    <button class="action-button view-details-btn" data-request-id="${request._id}">View Details</button>
                    <button class="action-button edit-status-btn" onclick="openStatusUpdateModal('${request._id}')">Update Status</button>
                    <button class="action-button delete-btn" onclick="deleteRequest('${request._id}')">Delete</button>
                </td>
            `;
        });

        // Attach event listeners to the "View Details" buttons
        document.querySelectorAll('.view-details-btn').forEach(button => {
            button.addEventListener('click', (event) => {
                const requestId = event.target.dataset.requestId;
                viewRequestDetails(requestId);
            });
        });

    } catch (error) {
        console.error('Error loading requests:', error);
        showNotification('Error loading requests: ' + error.message, 'error');
    }
}

// Function to view detailed request information
async function viewRequestDetails(requestId) {
    console.log('admin-dashboard.js: Attempting to view details for request ID:', requestId);
    const detailsContainer = document.getElementById('request-details-content');
    const modalTitle = document.getElementById('view-details-modal-title');
    if (!detailsContainer || !modalTitle) {
        console.error('admin-dashboard.js: Details container or modal title not found.');
        return;
    }

    detailsContainer.innerHTML = '<p>Loading request details...</p>';
    modalTitle.textContent = 'Request Details';

    try {
        const response = await fetch(`/api/requests/${requestId}`);
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Failed to fetch request details.');
        }
        const request = await response.json();
        console.log('admin-dashboard.js: Fetched request details:', request);

        modalTitle.textContent = `Request Details: ${request.serviceType}`;

        let submittedFormDataHtml = '';
        const serviceType = request.serviceType;
        const formFields = serviceFieldMap[serviceType] || [];

        if (formFields.length > 0) {
            submittedFormDataHtml += '<h3>Submitted Form Data:</h3>';
            submittedFormDataHtml += '<table class="details-table">';
            formFields.forEach(field => {
                const value = request.formData[field.name] !== undefined && request.formData[field.name] !== null ? request.formData[field.name] : 'Not provided';
                submittedFormDataHtml += `
                    <tr>
                        <td>${field.label}:</td>
                        <td>${value}</td>
                    </tr>
                `;
            });
            submittedFormDataHtml += '</table>';
        } else {
            // Fallback for unexpected service types or if formData isn't mapped
            if (request.formData && Object.keys(request.formData).length > 0) {
                submittedFormDataHtml += '<h3>Submitted Form Data:</h3>';
                submittedFormDataHtml += '<table class="details-table">';
                for (const key in request.formData) {
                    if (Object.hasOwnProperty.call(request.formData, key)) {
                        const value = request.formData[key] !== undefined && request.formData[key] !== null ? request.formData[key] : 'Not provided';
                        const label = key.replace(/_/g, ' ').replace(/(?:^|\s)\\S/g, function(a) { return a.toUpperCase(); }); // Basic formatting
                        submittedFormDataHtml += `
                            <tr>
                                <td>${label}:</td>
                                <td>${value}</td>
                            </tr>
                        `;
                    }
                }
                submittedFormDataHtml += '</table>';
            } else {
                submittedFormDataHtml += '<p>No form data submitted for this request.</p>';
            }
        }

        // Add admin-specific information
        const adminInfoHtml = `
            <div class="admin-info-section">
                <h3>Admin Information:</h3>
                <p><strong>Requested By:</strong> ${request.userId ? request.userId.email : 'Not available'},</p>
                <p><strong>Assigned To:</strong> ${request.assignedTo ? request.assignedTo.email : 'Not assigned'},</p>
                <p><strong>Priority:</strong> <span class="priority-badge priority-${request.priority?.toLowerCase() || 'normal'}">${request.priority || 'Normal'}</span>,</p>
                ${request.internalNotes ? `<p><strong>Internal Notes:</strong> ${request.internalNotes},</p>` : ''}
            </div>
        `;

        detailsContainer.innerHTML = `
            <p><strong>Request ID:</strong> ${request._id},</p>
            <p><strong>Service Type:</strong> ${request.serviceType},</p>
            <p><strong>Status:</strong> <span class="status-badge status-${request.status.toLowerCase()}">${request.status}</span>,</p>
            <p><strong>Date Submitted:</strong> ${new Date(request.submissionDate).toLocaleString()},</p>
            <p><strong>Last Updated:</strong> ${new Date(request.lastUpdated).toLocaleString()},</p>
            ${request.notes ? `<p><strong>Notes:</strong> ${request.notes},</p>` : ''}
            ${adminInfoHtml}
            ${submittedFormDataHtml}
        `;

        showViewDetailsFloat();

    } catch (error) {
        console.error('admin-dashboard.js: Error fetching request details:', error);
        detailsContainer.innerHTML = `<p style="color: red;">Error loading details: ${error.message}</p>`;
    }
}

// Function to print request details
function printRequestDetails() {
    const printContent = document.getElementById('request-details-content').innerHTML;
    const originalBody = document.body.innerHTML;
    document.body.innerHTML = `
        <div class="print-container">
            <h1>Request Details,</h1>
            ${printContent}
            <div class="print-footer">
                <p>Printed on: ${new Date().toLocaleString()},</p>
                <p>Chandra Travel and Tours,</p>
            </div>
        </div>
    `;
    window.print();
    document.body.innerHTML = originalBody;
    // Reload the page to restore original content and scripts
    location.reload();
}

// Function to show the View Details floating card
function showViewDetailsFloat() {
    const floatCard = document.getElementById('viewDetailsFloat');
    if (floatCard) {
        floatCard.classList.add('active'); // Add active class to make it visible
        console.log('admin-dashboard.js: showViewDetailsFloat called. floatCard is active:', floatCard.classList.contains('active'));
    } else {
        console.error('admin-dashboard.js: viewDetailsFloat element not found when trying to show.');
    }
}

// Function to close the View Details floating card
function closeViewDetailsFloat() {
    const float = document.getElementById('viewDetailsFloat');
    float.classList.remove('active');
}

// Show the status update modal (centered)
function openStatusUpdateModal(id) {
    console.log(`openStatusUpdateModal called with ID: ${id}`);
    const modal = document.getElementById('statusUpdateModal');
    document.getElementById('update-request-id').textContent = id;
    modal.classList.add('active');
    console.log('statusUpdateModal active class added.', modal.classList.contains('active'));
}

function closeStatusUpdateModal() {
    console.log('closeStatusUpdateModal called.');
    const modal = document.getElementById('statusUpdateModal');
    modal.classList.remove('active');
    console.log('statusUpdateModal active class removed.', modal.classList.contains('active'));
    // Clear the form fields when closing for a clean state for next open
    document.getElementById('new-status').value = 'Pending'; // Reset to default
    document.getElementById('status-notes').value = ''; // Clear notes
}

// Show stat float card
function showStatFloatCard(title, detailsHtml) {
    const statFloatCard = document.getElementById('statFloatCard');
    document.getElementById('statFloatTitle').textContent = title;
    document.getElementById('statFloatDetails').innerHTML = detailsHtml;
    statFloatCard.classList.add('active');
    console.log('statFloatCard active class added.', statFloatCard.classList.contains('active'));
}

// Close stat float card
function closeStatFloatCard() {
    const statFloatCard = document.getElementById('statFloatCard');
    statFloatCard.classList.remove('active');
    console.log('statFloatCard active class removed.', statFloatCard.classList.contains('active'));
}

// Update request status
async function updateRequestStatus(id, newStatus, notes) {
    console.log(`updateRequestStatus called with ID: ${id}, New Status: ${newStatus}, Notes: ${notes}`);
    try {
        const response = await fetch(`/api/admin/requests/${id}/status`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ status: newStatus, notes })
        });

        console.log(`Response status: ${response.status}, status text: ${response.statusText}`);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Network response not ok for status update:', response.status, errorText);
            throw new Error(`Failed to update status: ${response.status} - ${errorText}`);
        }

        const result = await response.json();
        showNotification(result.message || 'Status updated successfully!', 'success');
        closeStatusModal();
        loadRequests(); // Reload requests to reflect changes
    } catch (error) {
        console.error('Error updating request status:', error);
        showNotification('Error updating status: ' + error.message, 'error');
    }
}

// Export data to JSON (if needed, otherwise remove)
async function exportData() {
    try {
        const response = await fetch('/api/admin/export-requests');
        if (!response.ok) {
            throw new Error('Failed to export data');
        }
        const data = await response.json();
        // For simplicity, we'll just log it to console or trigger a download
        console.log('Exported Data:', data);
        
        // You can create a downloadable file here
        const jsonString = JSON.stringify(data, null, 2);
        const blob = new Blob([jsonString], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'requests_export.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showNotification('Data exported successfully!', 'success');

    } catch (error) {
        console.error('Error exporting data:', error);
        showNotification('Error exporting data', 'error');
    }
}

// Setup event listeners for filters and buttons
function setupEventListeners() {
    document.getElementById('status-filter').addEventListener('change', loadRequests);
    document.getElementById('service-filter').addEventListener('change', loadRequests);
    document.getElementById('date-from').addEventListener('change', loadRequests);
    document.getElementById('date-to').addEventListener('change', loadRequests);
    document.getElementById('search-filter').addEventListener('input', loadRequests);
    document.getElementById('refresh-button').addEventListener('click', refreshDashboard);
    document.getElementById('export-button').addEventListener('click', exportData);

    // Status update modal buttons
    const closeStatusModalBtn = document.getElementById('close-status-modal');
    const cancelStatusUpdateBtn = document.getElementById('cancel-status-update');
    const submitStatusUpdateBtn = document.getElementById('submit-status-update');

    console.log('setupEventListeners: Initializing status update modal buttons.');
    console.log('closeStatusModalBtn element:', closeStatusModalBtn);
    console.log('cancelStatusUpdateBtn element:', cancelStatusUpdateBtn);
    console.log('submitStatusUpdateBtn element:', submitStatusUpdateBtn);

    if (closeStatusModalBtn) {
        closeStatusModalBtn.addEventListener('click', closeStatusModal);
        console.log('closeStatusModalBtn listener added.');
    }
    if (cancelStatusUpdateBtn) {
        cancelStatusUpdateBtn.addEventListener('click', closeStatusModal); // Also close on cancel button click
        console.log('cancelStatusUpdateBtn listener added.');
    }
    if (submitStatusUpdateBtn) {
        submitStatusUpdateBtn.addEventListener('click', async () => {
            console.log('Submit Status Update button clicked!');
            const idElement = document.getElementById('update-request-id');
            const id = idElement ? idElement.textContent : null;
            const newStatus = document.getElementById('new-status').value;
            const notes = document.getElementById('status-notes').value;

            console.log('Attempting to update status with:');
            console.log('Request ID (from DOM):', id);
            console.log('New Status:', newStatus);
            console.log('Notes:', notes);

            if (!id) {
                console.error('Request ID is missing. Cannot update status.');
                showNotification('Error: Request ID is missing. Please try again.', 'error');
                return;
            }
            updateRequestStatus(id, newStatus, notes);
        });
        console.log('submitStatusUpdateBtn listener added.');
    }

    // Request details modal buttons
    // The close and print buttons for viewDetailsFloat are handled directly via onclick attributes in the HTML.
    // const closeDetailsModalBtn = document.getElementById('closeDetailsModalBtn');
    // const printDetailsBtn = document.getElementById('printDetailsBtn');

    // console.log('closeDetailsModalBtn element:', closeDetailsModalBtn);
    // console.log('printDetailsBtn element:', printDetailsBtn);

    // if (closeDetailsModalBtn) {
    //     closeDetailsModalBtn.addEventListener('click', closeModal);
    //     console.log('closeDetailsModalBtn listener added.');
    // }
    // if (printDetailsBtn) {
    //     printDetailsBtn.addEventListener('click', printRequestDetails);
    //     console.log('printDetailsBtn listener added.');
    // }

    // Initial load for date pickers if you use a library that needs activation
    // For simple input type="date", this might not be necessary.
}

// Close modal for request details
function closeModal() {
    console.log('Closing request details modal.');
    const viewDetailsFloat = document.getElementById('viewDetailsFloat');
    viewDetailsFloat.classList.remove('active'); // Refer to viewDetailsFloat for consistency
    console.log('viewDetailsFloat active class removed.', viewDetailsFloat.classList.contains('active'));
}

// Close status update modal
function closeStatusModal() {
    console.log('Closing status update modal.');
    const statusUpdateModal = document.getElementById('statusUpdateModal');
    statusUpdateModal.classList.remove('active');
    console.log('statusUpdateModal active class removed.', statusUpdateModal.classList.contains('active'));
    // Clear the form fields when closing for a clean state for next open
    document.getElementById('new-status').value = 'Pending'; // Reset to default
    document.getElementById('status-notes').value = ''; // Clear notes
}

// Show notification message
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    if (!notification) {
        console.warn('Notification element not found!');
        alert(message); // Fallback to alert if notification element is missing
        return;
    }
    console.log(`Showing notification: [${type}] ${message}`);
    notification.textContent = message;
    notification.className = `notification ${type} show`;
    setTimeout(() => {
        notification.className = notification.className.replace('show', '');
    }, 3000);
}

// Refresh dashboard data
function refreshDashboard() {
    console.log('Refreshing dashboard...');
    loadStatistics();
    loadCharts();
    loadRequests();
    showNotification('Dashboard refreshed!', 'info');
}

// Filter requests (already handled by loadRequests with query params, this might be redundant)
function filterRequests() {
    console.log('Filtering requests...');
    loadRequests(); // Simply re-load requests with current filters
}

// Placeholder for delete function
async function deleteRequest(id) {
    console.log(`Attempting to delete request with ID: ${id}`);
    if (!id || id === 'N/A') {
        showNotification('Invalid request ID', 'error');
        return;
    }

    if (confirm('Are you sure you want to delete this request? This action cannot be undone.')) {
        try {
            const response = await fetch(`/api/admin/requests/${id}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                const errorText = await response.text();
                try {
                    const errorData = JSON.parse(errorText);
                    throw new Error(errorData.message || `Failed to delete request: ${response.statusText}`);
                } catch (e) {
                    throw new Error(`Failed to delete request: ${response.statusText}`);
                }
            }

            showNotification('Request deleted successfully!', 'success');
            await loadRequests(); // Reload requests after deletion
        } catch (error) {
            console.error('Error deleting request:', error);
            showNotification(error.message || 'Error deleting request. Please try again.', 'error');
        }
    }
}

// Remove the serviceFieldMap definition and replace with import
document.write('<script src="/js/admin/service-field-map.js"></script>');