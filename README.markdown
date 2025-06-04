# Full-Stack Registration System

A full-stack app with a login-first frontend (Vercel) and Node.js backend (Render), featuring geolocation and MongoDB.

## Features
- Login page with “Not registered? Register” link.
- Geolocation modal for registration.
- Google-like UI with “Palatino Linotype” font.

## Structure
- `frontend/`: HTML/JSON for Vercel.
- `backend/`: Node.js/Express for Render.

## Local Testing
1. **Frontend**:
   ```bash
   cd frontend
   npm install -g serve
   serve -s .
   ```
   - Access at `http://localhost:3000`.
   - Set `backendUrl` in `index.html` to `http://localhost:3000`.
2. **Backend**:
   ```bash
   cd backend
   npm install
   ```
   - Create `.env`:
     ```plaintext
     MONGO_URI=mongodb+srv://deysaptaporna003:B89BVfTJU7JkEDnZ@cluster0.4gnaegm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
     PORT=3000
     ```
   - Start:
     ```bash
     npm start
     ```
3. **Debug**:
   - Open browser console (F12).
   - Check Network tab for failed `/public/countries.json` or `/public/adminOptions.json`.
   - Verify API calls to `backendUrl`.
   - Ensure MongoDB connection in terminal.

## Deployment
### Frontend (Vercel)
1. **Push**:
   ```bash
   cd full-stack-app
   git init
   git add .
   git commit -m "Fix login page functionality"
   git remote add origin https://github.com/your-username/full-stack-app.git
   git push -u origin main
   ```
2. **Deploy**:
   - Sign in to [Vercel](https://vercel.com).
   - Import repository.
   - Set `frontend` as root directory.
   - Deploy and note URL.
3. **Update Backend URL**:
   - Set `backendUrl` in `index.html` to Render URL.
   - Push:
     ```bash
     git add frontend/index.html
     git commit -m "Update backend URL"
     git push
     ```

### Backend (Render)
1. **Push**:
   - Ensure `backend` in repository.
2. **Deploy**:
   - Sign in to [Render](https://render.com).
   - New Web Service, connect GitHub.
   - Configure:
     - Root Directory: `backend`
     - Runtime: Node
     - Build Command: `npm install`
     - Start Command: `npm start`
     - Environment Variables:
       ```plaintext
       MONGO_URI=mongodb+srv://deysaptaporna003:B89BVfTJU7JkEDnZ@cluster0.4gnaegm.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0
       PORT=3000
       ```
   - Deploy and note URL.

## Debugging
- **Login Page Stuck**:
  - Console (F12): Look for errors like “Failed to fetch” or undefined variables.
  - Network tab: Ensure `/public/countries.json` and `/public/adminOptions.json` load (200 status).
  - Verify `backendUrl` is correct.
- **MongoDB**:
  - Whitelist IP in Atlas (`0.0.0.0/0` for testing).
  - Check terminal for connection errors.
- **Geolocation**:
  - Use HTTPS (Vercel) or `localhost`.
  - Check browser permissions.

## Notes
- **Images**: Use AWS S3 for production.
- **Security**: Add JWT for panels.
- **Logo**: Replace placeholder in `index.html`.