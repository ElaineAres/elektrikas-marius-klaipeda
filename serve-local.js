const http = require("http");
const fs = require("fs");
const path = require("path");

const port = Number(process.env.PORT) || 8081;
const root = __dirname;

const mimeTypes = {
  ".html": "text/html; charset=UTF-8",
  ".css": "text/css; charset=UTF-8",
  ".js": "application/javascript; charset=UTF-8",
  ".json": "application/json; charset=UTF-8",
  ".xml": "application/xml; charset=UTF-8",
  ".txt": "text/plain; charset=UTF-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".mp4": "video/mp4",
  ".webmanifest": "application/manifest+json; charset=UTF-8",
  ".yml": "text/yaml; charset=UTF-8",
  ".yaml": "text/yaml; charset=UTF-8"
};

function safePath(urlPath) {
  const decoded = decodeURIComponent((urlPath || "/").split("?")[0]);
  const rawPath = decoded === "/" ? "/index.html" : decoded;
  const resolved = path.resolve(root, `.${rawPath}`);
  return resolved.startsWith(root) ? resolved : null;
}

const server = http.createServer((req, res) => {
  const filePath = safePath(req.url);

  if (!filePath) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=UTF-8" });
    res.end("Forbidden");
    return;
  }

  fs.stat(filePath, (statError, stats) => {
    let target = filePath;

    if (!statError && stats.isDirectory()) {
      target = path.join(filePath, "index.html");
    }

    fs.readFile(target, (readError, data) => {
      if (readError) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=UTF-8" });
        res.end("Not found");
        return;
      }

      const ext = path.extname(target).toLowerCase();
      res.writeHead(200, {
        "Content-Type": mimeTypes[ext] || "application/octet-stream",
        "Cache-Control": "no-cache"
      });
      res.end(data);
    });
  });
});

server.listen(port, () => {
  console.log(`Elektrikas Marius local server running at http://localhost:${port}`);
});

server.on("error", (error) => {
  console.error(error.message);
  process.exit(1);
});
