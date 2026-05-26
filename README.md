# 🛡️ XSSafe - Interactive Anti-XSS Sanitizer Sandbox

**XSSafe** is a high-fidelity interactive sandbox application designed to educate developers and security professionals about Cross-Site Scripting (XSS) vulnerabilities, detection signatures, sanitization techniques, and browser-enforced Content Security Policy (CSP).

---

## 🚀 Key Features

* **🛡️ Two Rendering Modes**: Toggle between **Safe Mode** (which passes inputs through DOMPurify) and **Vulnerable Mode** (which injects raw HTML into the DOM via `dangerouslySetInnerHTML` to demonstrate exploits in real-time).
* **🧪 Layered Security Scanners**:
  * **Regex Detection Layer**: Active heuristic analysis matching over 17 distinct XSS patterns, categorizing them by severity (Critical, High, Medium, Low).
  * **Sanitization Layer**: Industry-standard parser-level purification using `DOMPurify` to safely strip malicious event handlers and scripts.
* **📂 XSS Payload Vault**: Access 24 pre-built, real-world XSS payloads across various categories:
  * Basic Script tags & cookie exfiltration
  * SVG XML vectors & HTML5-specific event handlers
  * Encoding & tokenization bypass techniques
  * Template injections (AngularJS, Vue)
  * Polyglot XSS scripts
* **📝 Security telemetry & Logs**: Keep track of block triggers and payload types through a persistent, real-time Attack Log.
* **🛡️ CSP Educational Dashboard**: Interactive breakdown of how Content Security Policy acts as a fallback layer in defense-in-depth security.

---

## 🛠️ Technology Stack

* **Frontend Framework**: React 19
* **Build System**: Vite 8
* **Styling**: Vanilla CSS (Rich dark themes, custom scrollbars, and glowing glassmorphic panels)
* **Libraries**: `dompurify` (for client-side HTML sanitization)

---

## 📦 Getting Started

### Prerequisites

* Node.js (v18 or higher recommended)
* npm (v9 or higher)

### Installation

1. Clone or copy the repository contents.
2. Install the package dependencies:
   ```bash
   npm install
   ```

### Running Locally

To run the development server:
```bash
npm run dev
```
Open your browser and navigate to the local address provided (typically `http://localhost:5173`).

---

## 🏗️ Production Build & Verification

To verify the app compiles cleanly and bundle the production files:
```bash
npm run build
```
This outputs optimized, minified production assets inside the `/dist` folder, ready to be hosted on any static file server.

To preview the built app locally:
```bash
npm run preview
```

---

## 🚀 Deployment Guide

This project is a static React application, making it highly portable. You can deploy it to any of the following platforms for free:

### 1. Vercel
1. Install Vercel CLI: `npm install -g vercel`
2. Run `vercel` from the root directory and follow the prompts.
3. *Alternative:* Link the repository directly to Vercel via GitHub for automatic CI/CD deployment on every push.

### 2. Netlify
1. Run `npm run build` to generate the `dist` folder.
2. Drag and drop the `dist` folder onto the [Netlify App Dashboard](https://app.netlify.com).
3. *Alternative:* Connect your repository for automated builds on push.

### 3. GitHub Pages
1. Install the gh-pages package: `npm install gh-pages --save-dev`
2. Add a `homepage` property to your `package.json` pointing to your URL:
   `"homepage": "http://<username>.github.io/<repository-name>"`
3. Add the following scripts to `package.json`:
   ```json
   "predeploy": "npm run build",
   "deploy": "gh-pages -d dist"
   ```
4. Deploy the application:
   ```bash
   npm run deploy
   ```

---

## 🛡️ License

This project is open-source and intended solely for security education and demonstration purposes.
