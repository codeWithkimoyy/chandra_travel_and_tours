# Chandra Travel and Tours

## Project Structure

```
├── js/
│   ├── admin/           # Admin-specific JavaScript files
│   │   ├── admin-dashboard.js
│   │   ├── updateAdminUser.js
│   │   ├── migrateRequests.js
│   │   └── migrateTo7CharIds.js
│   ├── client/          # Client-specific JavaScript files
│   │   ├── forms.js
│   │   └── my-requests.js
│   └── common/          # Shared JavaScript files
│       ├── auth.js
│       └── animations.js
├── server.js           # Main server file
├── package.json        # Project dependencies
└── HTML files         # All HTML files in root directory
```

## Setup Instructions

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the server:
   ```bash
   node server.js
   ```

3. Access the application:
   - Main site: http://localhost:3000
   - Admin dashboard: http://localhost:3000/admin-dashboard.html
   - Client dashboard: http://localhost:3000/my-requests.html

## File Organization

### Admin Files (`js/admin/`)
- `admin-dashboard.js`: Admin dashboard functionality
- `updateAdminUser.js`: Admin user management
- `migrateRequests.js`: Database migration utilities
- `migrateTo7CharIds.js`: ID format migration utilities

### Client Files (`js/client/`)
- `forms.js`: Form handling and submission
- `my-requests.js`: Client request management

### Common Files (`js/common/`)
- `auth.js`: Authentication and authorization
- `animations.js`: Shared animations and UI effects

## Troubleshooting

1. If scripts are not loading:
   - Clear browser cache
   - Check browser console for errors
   - Verify file paths in HTML files

2. If authentication fails:
   - Check server logs
   - Verify session configuration
   - Clear browser cookies

3. If forms don't submit:
   - Check browser console for errors
   - Verify network requests
   - Check server logs

## Development Guidelines

1. Keep admin and client code separate
2. Use common utilities for shared functionality
3. Follow the established file structure
4. Update this README when adding new files 