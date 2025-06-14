// Mapping of service types to their possible fields and labels (shared between admin and client)
const serviceFieldMap = {
  'Passport Appointment': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'sex', label: 'Sex' },
    { name: 'civil_status', label: 'Civil Status' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'appointment_date', label: 'Preferred Date' },
    { name: 'appointment_time', label: 'Preferred Time' },
    { name: 'appointment_type', label: 'Appointment Type' },
    { name: 'preferred_location', label: 'Preferred Location' }
  ],
  'Apostille': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'zipcode', label: 'Zipcode' },
    { name: 'document_type', label: 'Type of Document' },
    { name: 'issuing_office', label: 'Issuing Office/Agency' },
    { name: 'date_of_issue', label: 'Date of Issue' },
    { name: 'copies', label: 'Number of Copies to Apostille' },
    { name: 'receiver_name', label: "Receiver's Name" },
    { name: 'receiver_contact', label: 'Contact #' },
    { name: 'receiver_address', label: 'Complete Address (Receiver)' },
    { name: 'zipcode_receiver', label: 'Zipcode (Receiver)' }
  ],
  'PSA Birth Certificate': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'sex', label: 'Sex' },
    { name: 'mother_maidenname', label: "Mother's Maiden Name" },
    { name: 'father_name', label: "Father's Name" },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'zipcode', label: 'Zipcode' },
    { name: 'relationship', label: 'Relationship to Owner' },
    { name: 'purpose', label: 'Purpose of Request' },
    { name: 'copies', label: 'Number of Copies' }
  ],
  'PSA Marriage Certificate': [
    { name: 'husband_lastname', label: "Husband's Last Name" },
    { name: 'husband_firstname', label: "Husband's First Name" },
    { name: 'husband_middlename', label: "Husband's Middle Name" },
    { name: 'wife_maidenname', label: "Wife's Maiden Name" },
    { name: 'wife_firstname', label: "Wife's First Name" },
    { name: 'wife_middlename', label: "Wife's Middle Name" },
    { name: 'date_of_marriage', label: 'Date of Marriage' },
    { name: 'place_of_marriage', label: 'Place of Marriage' },
    { name: 'requestor_name', label: "Requestor's Name" },
    { name: 'relationship', label: 'Relationship to the owner' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'zipcode', label: 'Zipcode' },
    { name: 'purpose', label: 'Purpose of Request' },
    { name: 'copies', label: 'Number of Copies' }
  ],
  'PSA Death Certificate': [
    { name: 'lastname', label: "Deceased's Last Name" },
    { name: 'firstname', label: "Deceased's First Name" },
    { name: 'middlename', label: "Deceased's Middle Name" },
    { name: 'date_of_death', label: 'Date of Death' },
    { name: 'place_of_death', label: 'Place of Death' },
    { name: 'requestor_name', label: "Requestor's Name" },
    { name: 'relationship', label: 'Relationship to the owner' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'zipcode', label: 'Zipcode' },
    { name: 'purpose', label: 'Purpose of Request' },
    { name: 'copies', label: 'Number of Copies' }
  ],
  'CENOMAR': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'sex', label: 'Sex' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'zipcode', label: 'Zipcode' },
    { name: 'purpose', label: 'Purpose of CENOMAR' },
    { name: 'copies', label: 'Number of Copies' }
  ],
  'eReg': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'civilstatus', label: 'Civil Status' },
    { name: 'nationality', label: 'Nationality' },
    { name: 'religion', label: 'Religion' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'homephone', label: 'Home Phone' },
    { name: 'address', label: 'Complete Address' },
    { name: 'city', label: 'City' },
    { name: 'province', label: 'Province' },
    { name: 'postalcode', label: 'Postal Code' },
    { name: 'desired_service', label: 'Desired Service' },
    { name: 'other_service', label: 'Other Service (if specified)' },
    { name: 'previous_oec', label: 'Previous OEC Number' },
    { name: 'destination_country', label: 'Destination Country' },
    { name: 'employer_name', label: 'Employer Name' },
    { name: 'job_position', label: 'Job Position' },
    { name: 'appointment_date', label: 'Preferred Appointment Date' },
    { name: 'appointment_time', label: 'Preferred Appointment Time' },
    { name: 'purpose', label: 'Purpose of Application' },
    { name: 'special_requirements', label: 'Special Requirements' }
  ],
  'OEC Balik Manggagawa Appointment': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'civilstatus', label: 'Civil Status' },
    { name: 'nationality', label: 'Nationality' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'city', label: 'City' },
    { name: 'province', label: 'Province' },
    { name: 'postalcode', label: 'Postal Code' },
    { name: 'employer_name', label: 'Employer Name' },
    { name: 'job_position', label: 'Job Position' },
    { name: 'employment_start', label: 'Employment Start Date' },
    { name: 'employment_end', label: 'Employment End Date' },
    { name: 'previous_oec', label: 'Previous OEC Number' },
    { name: 'destination_country', label: 'Destination Country' },
    { name: 'flight_date', label: 'Flight Date' },
    { name: 'flight_time', label: 'Flight Time' },
    { name: 'airline', label: 'Airline' },
    { name: 'flight_number', label: 'Flight Number' },
    { name: 'appointment_date', label: 'Preferred Appointment Date' },
    { name: 'appointment_time', label: 'Preferred Appointment Time' },
    { name: 'special_requirements', label: 'Special Requirements' }
  ],
  'OEC Exemption': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'civilstatus', label: 'Civil Status' },
    { name: 'nationality', label: 'Nationality' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'city', label: 'City' },
    { name: 'province', label: 'Province' },
    { name: 'postalcode', label: 'Postal Code' },
    { name: 'employer_name', label: 'Employer Name' },
    { name: 'job_position', label: 'Job Position' },
    { name: 'previous_oec', label: 'Previous OEC Number' },
    { name: 'destination_country', label: 'Destination Country' },
    { name: 'flight_date', label: 'Flight Date' },
    { name: 'flight_time', label: 'Flight Time' },
    { name: 'airline', label: 'Airline' },
    { name: 'flight_number', label: 'Flight Number' },
    { name: 'special_requirements', label: 'Special Requirements' }
  ],
  'Quarantine Certificate': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'nationality', label: 'Nationality' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'certificate_type', label: 'Type of Certificate' },
    { name: 'other_certificate', label: 'Other Certificate (if specified)' },
    { name: 'purpose', label: 'Purpose of Application' },
    { name: 'destination_country', label: 'Country of Destination' },
    { name: 'appointment_date', label: 'Preferred Appointment Date' },
    { name: 'appointment_time', label: 'Preferred Appointment Time' },
    { name: 'special_requirements', label: 'Special Requirements' }
  ],
  'Quarantine Vaccination': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'nationality', label: 'Nationality' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'vaccine_type', label: 'Type of Vaccine' },
    { name: 'dose_number', label: 'Dose Number' },
    { name: 'vaccination_date', label: 'Date of Vaccination' },
    { name: 'vaccination_place', label: 'Place of Vaccination' },
    { name: 'purpose', label: 'Purpose of Vaccination' },
    { name: 'destination_country', label: 'Country of Destination' },
    { name: 'appointment_date', label: 'Preferred Appointment Date' },
    { name: 'appointment_time', label: 'Preferred Appointment Time' },
    { name: 'special_requirements', label: 'Special Requirements' }
  ],
  'MARINA SRB': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'sex', label: 'Sex' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'appointment_date', label: 'Preferred Date' },
    { name: 'appointment_time', label: 'Preferred Time' }
  ],
  'MARINA SID': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'sex', label: 'Sex' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'appointment_date', label: 'Preferred Date' },
    { name: 'appointment_time', label: 'Preferred Time' }
  ],
  'Airline Ticketing': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'departure_city', label: 'Departure City' },
    { name: 'arrival_city', label: 'Arrival City' },
    { name: 'departure_date', label: 'Departure Date' },
    { name: 'return_date', label: 'Return Date' },
    { name: 'preferred_airline', label: 'Preferred Airline' }
  ],
  'Tour Package': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'tour_package', label: 'Tour Package' },
    { name: 'other_tour', label: 'Other Tour (if specified)' },
    { name: 'travelers', label: 'Number of Travelers' },
    { name: 'preferred_date', label: 'Preferred Date' }
  ],
  'Flights/Hotel Booking': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'checkin_date', label: 'Check-in Date' },
    { name: 'checkout_date', label: 'Check-out Date' },
    { name: 'guests', label: 'Number of Guests' },
    { name: 'room_type', label: 'Room Type' },
    { name: 'other_room', label: 'Other Room (if specified)' }
  ],
  'Ferry/Bus Booking': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'departure_city', label: 'Departure City' },
    { name: 'arrival_city', label: 'Arrival City' },
    { name: 'departure_date', label: 'Departure Date' },
    { name: 'return_date', label: 'Return Date' },
    { name: 'preferred_service', label: 'Preferred Service' },
    { name: 'other_service', label: 'Other Service (if specified)' }
  ],
  'Travel Insurance': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'insurance_plan', label: 'Insurance Plan' },
    { name: 'other_plan', label: 'Other Plan (if specified)' },
    { name: 'coverage_start', label: 'Coverage Start Date' },
    { name: 'coverage_end', label: 'Coverage End Date' }
  ],
  'Visa Assistance': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'destination_country', label: 'Destination Country' },
    { name: 'purpose', label: 'Purpose of Travel' },
    { name: 'travel_date', label: 'Travel Date' }
  ],
  'NBI Clearance': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'civilstatus', label: 'Civil Status' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'service_type', label: 'Service Type' },
    { name: 'purpose', label: 'Purpose' },
    { name: 'copies', label: 'Number of Copies' },
    { name: 'appointment_date', label: 'Preferred Date' },
    { name: 'appointment_time', label: 'Preferred Time' }
  ],
  'Police Clearance Appointment': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'birthplace', label: 'Place of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'civilstatus', label: 'Civil Status' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'purpose', label: 'Purpose' },
    { name: 'copies', label: 'Number of Copies' },
    { name: 'appointment_date', label: 'Preferred Date' },
    { name: 'appointment_time', label: 'Preferred Time' }
  ],
  'Embassy Stamping and Translation': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'document_type', label: 'Type of Document' },
    { name: 'other_document', label: 'Other Document (if specified)' },
    { name: 'copies', label: 'Number of Copies' },
    { name: 'embassy', label: 'Target Embassy' },
    { name: 'purpose', label: 'Purpose' }
  ],
  'CAV and CANA Assistance': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'application_type', label: 'Type of Application' },
    { name: 'school', label: 'School/University' },
    { name: 'course', label: 'Course/Degree' },
    { name: 'year_graduated', label: 'Year Graduated' },
    { name: 'purpose', label: 'Purpose' }
  ],
  'LTO Certificate': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'certificate_type', label: 'Type of Certificate' },
    { name: 'other_certificate', label: 'Other Certificate (if specified)' },
    { name: 'purpose', label: 'Purpose' }
  ],
  "VOTER'S Certificate from Comelec Main": [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'voter_id', label: "Voter's ID Number" },
    { name: 'precinct_number', label: 'Precinct Number' },
    { name: 'purpose', label: 'Purpose' }
  ],
  'CFO Appointment': [
    { name: 'lastname', label: 'Last Name' },
    { name: 'firstname', label: 'First Name' },
    { name: 'middlename', label: 'Middle Name' },
    { name: 'dob', label: 'Date of Birth' },
    { name: 'gender', label: 'Gender' },
    { name: 'civilstatus', label: 'Civil Status' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'address', label: 'Complete Address' },
    { name: 'seminar_type', label: 'Type of Seminar' },
    { name: 'other_seminar', label: 'Other Seminar (if specified)' },
    { name: 'appointment_date', label: 'Preferred Date' },
    { name: 'appointment_time', label: 'Preferred Time' }
  ],
  'Load Available and Bills Payment': [
    { name: 'full_name', label: 'Full Name' },
    { name: 'email', label: 'Email Address' },
    { name: 'mobile', label: 'Mobile Number' },
    { name: 'account_number', label: 'Account Number' },
    { name: 'payment_amount', label: 'Payment Amount' },
    { name: 'payment_type', label: 'Payment Type' }
  ],
  'Contact Us Message': [
    { name: 'name', label: 'Name' },
    { name: 'email', label: 'Email' },
    { name: 'subject', label: 'Subject' },
    { name: 'message', label: 'Message' }
  ]
};

// Export the serviceFieldMap for use in other files
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { serviceFieldMap };
} else {
  // For browser environment, make it globally available
  window.serviceFieldMap = serviceFieldMap;
} 