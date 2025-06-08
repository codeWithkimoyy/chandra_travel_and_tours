document.addEventListener('DOMContentLoaded', function () {
    const buttonFormPairs = [
        ['psaBirthBtn', 'psaBirthFormContainer'],
        ['psaMarriageBtn', 'psaMarriageFormContainer'],
        ['psaDeathBtn', 'psaDeathFormContainer'],
        ['apostilleBtn', 'apostilleFormContainer'],
        ['eregBtn', 'eregFormContainer'],
        ['oecBmBtn', 'oecBmFormContainer'],
        ['oecExBtn', 'oecExFormContainer'],
        ['nbiBtn', 'nbiFormContainer'],
        ['policeBtn', 'policeFormContainer'],
        ['quarantineCertBtn', 'quarantineCertFormContainer'],
        ['quarantineVaccBtn', 'quarantineVaccFormContainer'],
        ['marinaSrbBtn', 'marinaSrbFormContainer'],
        ['marinaSidBtn', 'marinaSidFormContainer'],
        ['visaBtn', 'visaFormContainer'],
        ['insuranceBtn', 'insuranceFormContainer'],
        ['bookingBtn', 'bookingFormContainer'],
        ['ferryBtn', 'ferryFormContainer'],
        ['tourBtn', 'tourFormContainer'],
        ['cfoBtn', 'cfoFormContainer'],
        ['passportBtn', 'passportFormContainer'],
        ['cenomarBtn', 'cenomarFormContainer'],
        ['embassyBtn', 'embassyFormContainer'],
        ['cavCanaBtn', 'cavCanaFormContainer'],
        ['ltoBtn', 'ltoFormContainer'],
        ['votersBtn', 'votersFormContainer'],
        ['loadBillsBtn', 'loadBillsFormContainer'],
        ['airlineTicketingBtn', 'airlineTicketingFormContainer']
    ];

    function hideAllForms() {
        buttonFormPairs.forEach(([_, containerId]) => {
            const container = document.getElementById(containerId);
            if (container) {
                // Handle both class="hidden" and style="display:none"
                container.classList.add('hidden');
                container.style.display = 'none';
            }
        });
    }

    function showForm(container) {
        container.classList.remove('hidden');
        container.style.display = 'block';
        container.scrollIntoView({ behavior: 'smooth' });
    }

    buttonFormPairs.forEach(([btnId, containerId]) => {
        const button = document.getElementById(btnId);
        const container = document.getElementById(containerId);
        if (button && container) {
            button.addEventListener('click', () => {
                const isHidden = container.classList.contains('hidden') || container.style.display === 'none';
                hideAllForms();
                if (isHidden) {
                    showForm(container);
                }
            });
        } else {
            console.warn(`Button or form container not found: ${btnId} -> ${containerId}`);
        }
    });

    const forms = document.querySelectorAll('.service-form');
    forms.forEach(form => {
        form.addEventListener('submit', async function (e) {
            e.preventDefault();
            
            // Check if user is authenticated
            if (typeof isAuthenticated !== 'function') {
                console.error('Authentication function not found');
                alert('Authentication system error. Please try again later.');
                return;
            }

            // First check auth status
            try {
                const authResponse = await fetch('/api/auth/status', {
                    credentials: 'include' // Important for session cookies
                });
                
                if (!authResponse.ok) {
                    const authData = await authResponse.json();
                    if (authData.code === 'SESSION_INVALID') {
                        alert('Your session has expired. Please log in again.');
                        window.location.href = '/index.html';
                        return;
                    }
                    throw new Error(authData.message || 'Authentication failed');
                }

                const authData = await authResponse.json();
                if (!authData.authenticated) {
                    alert('Please log in to submit forms. You will be redirected to the login page.');
                    window.location.href = '/index.html';
                    return;
                }
            } catch (error) {
                console.error('Auth check failed:', error);
                alert('Authentication check failed. Please try logging in again.');
                window.location.href = '/index.html';
                return;
            }

            // Get the form ID to determine which endpoint to use
            const formId = form.id;
            console.log('Submitting form:', formId);

            // Map form IDs to API endpoints
            const endpointMap = {
                'psaBirthForm': '/api/psa-birth',
                'psaMarriageForm': '/api/psa-marriage',
                'psaDeathForm': '/api/psa-death',
                'marinaSrbForm': '/api/marina-srb',
                'marinaSidForm': '/api/marina-sid',
                'visaForm': '/api/visa',
                'insuranceForm': '/api/insurance',
                'bookingForm': '/api/booking',
                'ferryForm': '/api/ferry',
                'tourForm': '/api/tour',
                'cfoForm': '/api/cfo',
                'apostilleForm': '/api/apostille',
                'oecBmForm': '/api/oec-bm',
                'oecExForm': '/api/oec-exemption',
                'nbiForm': '/api/nbi',
                'eregForm': '/api/ereg',
                'quarantineCertForm': '/api/quarantine-cert',
                'quarantineVaccForm': '/api/quarantine-vacc',
                'passportForm': '/api/passport',
                'cenomarForm': '/api/cenomar',
                'embassyForm': '/api/embassy',
                'cavCanaForm': '/api/cav-cana',
                'ltoForm': '/api/lto',
                'votersForm': '/api/voters',
                'loadBillsForm': '/api/load-bills',
                'policeForm': '/api/police',
                'airlineTicketingForm': '/api/airline-ticketing',
                'contactForm': '/api/contact'
            };

            const endpoint = endpointMap[formId];
            if (!endpoint) {
                console.error('No endpoint mapped for form:', formId);
                alert('Form configuration error. Please contact support.');
                return;
            }

            // Disable submit button to prevent double submission
            const submitButton = form.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Submitting...';
            }

            try {
                // Validate required fields
                const requiredFields = form.querySelectorAll('[required]');
                const missingFields = Array.from(requiredFields)
                    .filter(field => !field.value.trim())
                    .map(field => field.name || field.id || 'Required field');
                
                if (missingFields.length > 0) {
                    throw new Error(`Please fill in all required fields: ${missingFields.join(', ')}`);
                }

                // Get form data
                const formData = new FormData(form);
                const data = Object.fromEntries(formData.entries());
                
                // Clean and validate form data
                Object.keys(data).forEach(key => {
                    if (typeof data[key] === 'string') {
                        data[key] = data[key].trim();
                    }
                });

                console.log('Submitting form data:', data);
                
                // Submit to server
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(data),
                    credentials: 'include' // Important for session cookies
                });
                
                // Handle non-JSON responses
                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    throw new Error('Server returned invalid response format');
                }

                const result = await response.json();
                console.log('[forms.js] Server response ok:', response.ok);
                console.log('[forms.js] Server response result:', result);
                
                if (!response.ok) {
                    if (result.code === 'SESSION_INVALID') {
                        alert('Your session has expired. Please log in again.');
                        window.location.href = '/index.html';
                        return;
                    }
                    throw new Error(result.message || `Server error: ${response.status}`);
                }
                
                if (result.message && result.requestId) {
                    // Show success message with request ID
                    alert(`${result.message}\nYour Request ID is: ${result.requestId}\nPlease keep this ID for future reference.`);
                    form.reset();
                    hideAllForms();
                    
                    // Redirect to my-requests page after successful submission
                    setTimeout(() => {
                        window.location.href = '/my-requests.html';
                    }, 2000);
                } else {
                    throw new Error('Server response missing required fields');
                }
            } catch (error) {
                console.error('Error submitting form:', error);
                alert(`Error submitting form: ${error.message || 'An unexpected error occurred. Please try again.'}`);
            } finally {
                // Re-enable submit button
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.textContent = 'Submit';
                }
            }
        });
    });

    // Handle the contact form separately as it doesn't require authentication
    const contactForm = document.getElementById('contactForm');
    if (contactForm) {
        contactForm.addEventListener('submit', async function(e) {
            e.preventDefault();

            const submitButton = contactForm.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Sending...';
            }

            const formData = new FormData(this);
            const data = Object.fromEntries(formData.entries());

            try {
                const response = await fetch('/api/contact', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if (!response.ok) {
                    throw new Error(result.message || `Server error: ${response.status}`);
                }

                alert(result.message || 'Contact message sent!');
                this.reset();
                // You might want to hide the form or show a success message on the page
                // document.getElementById('contactFormContainer').classList.add('hidden'); 

            } catch (error) {
                console.error('Error submitting contact form:', error);
                alert(`Error sending message: ${error.message || 'Please try again.'}`);
            } finally {
                if (submitButton) {
                    submitButton.disabled = false;
                    submitButton.textContent = 'Send Message';
                }
            }
        });
    }
});
