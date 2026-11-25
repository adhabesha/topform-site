# Topform Technologies website (Go)

Run locally:  `go run .`  then open http://localhost:8080
Admin:        http://localhost:8080/admin  (on localhost the password is `admin`)

## Admin on Render (important)
Set these in Render > your service > Environment:
- ADMIN_PASSWORD  = a strong password (admin is disabled online without it)
- GITHUB_TOKEN    = fine-grained token, repo access to this repo, Contents: Read and write
- GITHUB_REPO     = adhabesha/topform-redesign
Without the GitHub variables, edits and uploads work but are lost when Render restarts the server.
With them, every save/upload is committed to the repo (data/content.json, data/uploads/*) and the site redeploys itself.

Homepage: static/index.html (glass-panel hero, spinning shield, sky slideshow). Slideshow images: Admin > Images & media > "Home page hero". Old homepage is kept at /home-2.
Files: main.go (server, admin API, uploads), static/index.html (site), static/admin.html (admin), static/defaults.js (default content),
static/img (built-in images), data/ (saved content + uploads)
