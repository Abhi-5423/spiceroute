# SpiceRoute Recipe Studio

## Included

- Responsive recipe site in `paste.html`
- Python backend in `server.py`
- Login/signup with signed session cookies
- Search results ranked to the top for related recipe queries
- Optional MongoDB storage for users
- SQLite fallback when MongoDB is not configured

## Run locally

1. Install dependencies:
   `pip install -r requirements.txt`
2. Set environment variables from `.env.example` if needed.
3. Start the server:
   `python server.py`
4. Open:
   `http://127.0.0.1:8000/`

## GitHub

1. Create a new empty GitHub repository.
2. In this project folder run:
   `git init`
3. Add files:
   `git add .`
4. Commit:
   `git commit -m "Initial SpiceRoute app"`
5. Connect your repo:
   `git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPO.git`
6. Push:
   `git branch -M main`
   `git push -u origin main`

`.gitignore` already excludes local database files, logs, cache files, and `.env`.

## Render publish

This repo includes `render.yaml`, so Render can deploy it as a single Python web service.

1. Push this folder to GitHub.
2. Create a new Render account and choose `New +` -> `Blueprint`.
3. Select your GitHub repo.
4. In Render set:
   - `MONGODB_URI` to your MongoDB Atlas connection string
5. Render will use:
   - build command: `pip install -r requirements.txt`
   - start command: `python server.py`

## Search indexing

After the site is live on Render, finish these steps so it can be found in search engines:

1. Open your live site URL and confirm the homepage loads.
2. Open `/robots.txt` and `/sitemap.xml` on the live site and confirm both load.
3. In Google Search Console:
   - add your site as a property
   - submit your sitemap URL: `https://YOUR-LIVE-DOMAIN/sitemap.xml`
   - request indexing for the homepage
4. In Bing Webmaster Tools:
   - add the same site
   - submit the same sitemap URL
5. Wait for indexing. Search appearance is not instant and can take days or weeks.

## Production notes

- Set a strong `SESSION_SECRET`
- Set `SPICEROUTE_SECURE_COOKIES=1` when serving over HTTPS
- Use a real MongoDB connection string in `MONGODB_URI`
- The server automatically reads host `0.0.0.0` and the platform `PORT`

## Limitation in this workspace

This Codex workspace can prepare the files, but it cannot finish GitHub login, create your GitHub repo, or publish online without your browser/account access and local `git` installation.
