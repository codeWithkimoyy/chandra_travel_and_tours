// Check if user is authenticated and redirect if not
document.addEventListener('DOMContentLoaded', async () => {
    console.log('my-requests.js: DOMContentLoaded event fired.');
    // Wait for the authentication check to complete
    const authStatus = await waitForAuthCheck();

    if (!authStatus.isAuthenticated) {
        console.log("Redirecting unauthenticated user from my requests page.");
        window.location.href = '/'; // Redirect to home if not logged in
        return;
    }

    console.log("User is authenticated. Loading my requests.");
    // Load the current user's requests
    await loadMyRequests();
});

// Function to load requests for the logged-in user
async function loadMyRequests() {
    console.log('my-requests.js: === loadMyRequests function START ===');
    const tbody = document.getElementById('my-requests-table-body');
    if (!tbody) {
        console.error('my-requests.js: Table body #my-requests-table-body not found.');
        return; // Ensure the table body exists
    }

    try {
        console.log('my-requests.js: About to fetch /api/my-requests.');
        // Fetch requests for the current user
        const response = await fetch('/api/my-requests');
        console.log('my-requests.js: Fetch response received:', response); // Debugging: Check response object

        if (!response.ok) {
            console.error(`my-requests.js: Network response not ok for /api/my-requests: ${response.status}`);
            // Handle cases where the user is not found or other errors occur
            if (response.status === 401) {
                 // User is not authenticated, although we checked above, 
                 // this is a server-side safety net.
                window.location.href = '/';
            } else {
                throw new Error(`Failed to fetch requests: ${response.statusText}`);
            }
        }

        const requests = await response.json();
        console.log('my-requests.js: Received requests data:', requests);

        // Initialize counts
        let pendingCount = 0;
        let approvedCount = 0;
        let totalCount = requests.length;
        let recentCount = 0;

        // Calculate recent requests (e.g., last 7 days)
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

        // Clear existing table rows
        tbody.innerHTML = '';

        if (requests.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5">No requests submitted yet.</td></tr>';
            document.getElementById('pending-count').textContent = 0;
            document.getElementById('approved-count').textContent = 0;
            document.getElementById('total-count').textContent = 0;
            document.getElementById('recent-count').textContent = 0;
            return;
        }

        // Populate the table with requests and calculate counts
        requests.forEach(request => {
            if (request.status === 'Pending') {
                pendingCount++;
            }
            if (request.status === 'Approved') {
                approvedCount++;
            }
            // Check for recent requests
            const submissionDate = new Date(request.submissionDate);
            if (submissionDate >= sevenDaysAgo) {
                recentCount++;
            }

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${request._id}</td>
                <td>${request.serviceType}</td>
                <td>${new Date(request.submissionDate).toLocaleDateString()}</td>
                <td><span class="status-badge status-${request.status.toLowerCase()}">${request.status}</span></td>
                <td>
                    <button onclick="viewRequestDetails('${request._id}')" class="action-button view-details-btn">View Details</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Update dashboard statistics
        document.getElementById('pending-count').textContent = pendingCount;
        document.getElementById('approved-count').textContent = approvedCount;
        document.getElementById('total-count').textContent = totalCount;
        document.getElementById('recent-count').textContent = recentCount;

    } catch (error) {
        console.error('my-requests.js: Error loading user requests:', error);
        tbody.innerHTML = '<tr><td colspan="5" style="color: red;">Error loading requests. Please try again.</td></tr>';
    }
    console.log('my-requests.js: === loadMyRequests function END ===');
}

// Function to refresh the dashboard
async function refreshDashboard() {
    console.log('my-requests.js: Refreshing dashboard...');
    await loadMyRequests();
    console.log('my-requests.js: Dashboard refreshed.');
}

// Function to export requests
async function exportMyRequests() {
    console.log('my-requests.js: Attempting to export requests...');
    try {
        const response = await fetch('/api/my-requests');
        if (!response.ok) {
            throw new Error(`Failed to fetch requests for export: ${response.statusText}`);
        }
        const requests = await response.json();

        if (requests.length === 0) {
            alert('No requests to export.');
            return;
        }

        // Convert JSON to CSV (simplified example)
        const headers = ['Request ID', 'Service Type', 'Date Submitted', 'Status'];
        const csvRows = [];
        csvRows.push(headers.join(','));

        requests.forEach(request => {
            const row = [
                `"${request._id}"`,
                `"${request.serviceType}"`,
                `"${new Date(request.submissionDate).toLocaleDateString()}"`,
                `"${request.status}"`
            ];
            csvRows.push(row.join(','));
        });

        const csvString = csvRows.join('\n');
        const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.setAttribute('download', 'my_requests.csv');
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        alert('Requests exported successfully as my_requests.csv!');
        console.log('my-requests.js: Requests exported.');

    } catch (error) {
        console.error('my-requests.js: Error exporting requests:', error);
        alert(`Error exporting requests: ${error.message}`);
    }
}

// Function to show the View Details floating card
function showViewDetailsFloat() {
    const floatCard = document.getElementById('viewDetailsFloat');
    if (floatCard) {
        floatCard.classList.add('active'); // Add active class to make it visible
        console.log('my-requests.js: showViewDetailsFloat called. floatCard is active:', floatCard.classList.contains('active'));
    } else {
        console.error('my-requests.js: viewDetailsFloat element not found when trying to show.');
    }
}

// Function to close the View Details floating card
function closeViewDetailsFloat() {
    const floatCard = document.getElementById('viewDetailsFloat');
    if (floatCard) {
        floatCard.classList.remove('active'); // Remove active class to hide it
    }
}

// Function to view detailed request information
async function viewRequestDetails(requestId) {
    console.log('my-requests.js: Attempting to view details for request ID:', requestId);
    const detailsContainer = document.getElementById('request-details-content');
    const modalTitle = document.getElementById('view-details-modal-title');
    if (!detailsContainer || !modalTitle) {
        console.error('my-requests.js: Details container or modal title not found.');
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
        console.log('my-requests.js: Fetched request details:', request);

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

        detailsContainer.innerHTML = `
            <p><strong>Request ID:</strong> ${request._id}</p>
            <p><strong>Service Type:</strong> ${request.serviceType}</p>
            <p><strong>Status:</strong> <span class="status-badge status-${request.status.toLowerCase()}">${request.status}</span></p>
            <p><strong>Date Submitted:</strong> ${new Date(request.submissionDate).toLocaleString()}</p>
            <p><strong>Last Updated:</strong> ${new Date(request.lastUpdated).toLocaleString()}</p>
            ${request.notes ? `<p><strong>Notes:</strong> ${request.notes}</p>` : ''}
            ${submittedFormDataHtml}
        `;

        showViewDetailsFloat();

    } catch (error) {
        console.error('my-requests.js: Error fetching request details:', error);
        detailsContainer.innerHTML = `<p style="color: red;">Error loading details: ${error.message}</p>`;
    }
}

// Function to print request details
function printRequestDetails() {
    const printContent = document.getElementById('viewDetailsFloat').innerHTML;
    const originalBody = document.body.innerHTML;
    document.body.innerHTML = printContent;
    window.print();
    document.body.innerHTML = originalBody;
    // Reloads the page to restore original content and scripts, might be disruptive
    // Consider a more sophisticated approach for production if needed.
    location.reload();
}

// Function to filter requests (existing from before)
function filterMyRequests() {
    const statusFilter = document.getElementById('my-status-filter').value;
    const serviceFilter = document.getElementById('my-service-filter').value;
    const dateFilter = document.getElementById('my-date-filter').value;
    const searchFilter = document.getElementById('my-search-filter').value.toLowerCase();

    const tbody = document.getElementById('my-requests-table-body');
    if (!tbody) {
        console.error('my-requests.js: Table body #my-requests-table-body not found for filtering.');
        return;
    }

    const rows = tbody.getElementsByTagName('tr');
    let hasVisibleRequests = false;

    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const requestId = row.cells[0].textContent;
        const serviceType = row.cells[1].textContent;
        const dateSubmitted = new Date(row.cells[2].textContent).toISOString().split('T')[0]; // YYYY-MM-DD
        const status = row.cells[3].textContent;

        const matchesStatus = (statusFilter === 'all' || status.toLowerCase() === statusFilter);

        let matchesService = true;
        if (serviceFilter !== 'all') {
            if (serviceFilter === 'psa') {
                matchesService = serviceType.startsWith('PSA');
            } else if (serviceFilter === 'passport') {
                matchesService = serviceType.includes('Passport');
            } else if (serviceFilter === 'visa') {
                matchesService = serviceType.includes('Visa');
            } else if (serviceFilter === 'other') {
                matchesService = !(serviceType.startsWith('PSA') || serviceType.includes('Passport') || serviceType.includes('Visa'));
            } else {
                matchesService = serviceType.toLowerCase().includes(serviceFilter);
            }
        }

        const matchesDate = (dateFilter === '' || dateSubmitted === dateFilter);
        const matchesSearch = (searchFilter === '' ||
            requestId.toLowerCase().includes(searchFilter) ||
            serviceType.toLowerCase().includes(searchFilter) ||
            status.toLowerCase().includes(searchFilter) ||
            row.cells[4].textContent.toLowerCase().includes(searchFilter) // Assuming form data might be searchable here
        );

        if (matchesStatus && matchesService && matchesDate && matchesSearch) {
            row.style.display = '';
            hasVisibleRequests = true;
        } else {
            row.style.display = 'none';
        }
    }

    const noRequestsMessage = document.getElementById('no-requests-message');
    if (noRequestsMessage) {
        noRequestsMessage.style.display = hasVisibleRequests ? 'none' : 'flex';
    }
}

// Ensure auth.js is loaded and available before proceeding
// This is no longer strictly necessary due to waitForAuthCheck, but good practice
// setTimeout(() => {
//     if (typeof isAuthenticated !== 'function') {
//         console.error('auth.js not loaded or isAuthenticated function not available.');
//         // Potentially display an error message to the user
//     }
// }, 100); // Small delay to wait for auth.js

// Remove the serviceFieldMap definition and replace with import
document.write('<script src="/js/admin/service-field-map.js"></script>');
