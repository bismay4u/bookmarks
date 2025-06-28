# 📚 My Bookmarks

**My Bookmarks** is a self-hosted, scalable bookmarking software designed for public access and powered by MySQL. It provides a clean, organized, and extensible way to store and manage your bookmarks as browser-based solutions.

After the shutdown of Pocket, I found myself looking for an alternative that allowed not just storing links, but organizing them in a meaningful way. That inspired the creation of this open-source project, so that others in a similar situation can also benefit from it.

---

## 🚀 Features

* Easy to deploy and self-host
* Scalable architecture powered by Node.js and MySQL
* Automatically initializes database schema
* Lightweight and minimalistic design
* Ready for public availability (no login required for now)

---

## 🛠️ Hosting Instructions

To get started, follow these steps:

### Prerequisites

* Node.js (v20+)
* PM2 (for process management)
* MySQL database

### Setup

1. **Download and extract** the ZIP archive of the project.

2. **Create environment config:**

   ```bash
   cp env_sample .env
   ```

3. **Edit `.env`** and configure your MySQL database connection.

   > *Note: Only the database needs to be created manually. The application will auto-create the required tables.*

4. **Start the application** using one of the following commands:

   ```bash
   npm start
   # or
   node index.js
   # or (recommended for production)
   pm2 start ecosystem.config.js
   ```

5. **Access the application:**
   Open [http://localhost:3000](http://localhost:3000) in your browser.

6. **Optional (for public hosting):**
   Use a reverse proxy like **Nginx** to expose the service publicly.

---

### ⚠️ Note

Authentication is **not yet implemented**. The system is currently open to public access. Login and security features are planned for a future release.

---

## 🙌 Happy Bookmarking!

Feel free to fork, modify, and contribute to the project. Let’s build a better way to manage bookmarks—together.

