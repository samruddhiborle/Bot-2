const crypto = require("crypto");
const path = require("path");

const express = require("express");
const dotenv = require("dotenv");

const { DataStore } = require("./src/services/data-store");

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

const cookieName = "security_robot_session";
const sessionTtlMs = 1000 * 60 * 60 * 12;
const loginWindowMs = 1000 * 60 * 10;
const maxFailedLogins = 5;
const loginAttempts = new Map();

const authPassword = process.env.AUTH_PASSWORD || "";
const authPin = process.env.AUTH_PIN || "";
const sessionSecret = process.env.SESSION_SECRET || "replace-me-before-production";
const ingestToken = process.env.DEVICE_INGEST_TOKEN || "";
const esp32CaptureUrl = process.env.ESP32_CAM_CAPTURE_URL || "";
const esp32SharedSecret = process.env.ESP32_CAM_SHARED_SECRET || "";
const firebaseWebConfig = {
  apiKey: process.env.FIREBASE_WEB_API_KEY || "",
  authDomain: process.env.FIREBASE_WEB_AUTH_DOMAIN || "",
  databaseURL: process.env.FIREBASE_WEB_DATABASE_URL || "",
  projectId: process.env.FIREBASE_WEB_PROJECT_ID || "",
  storageBucket: process.env.FIREBASE_WEB_STORAGE_BUCKET || "",
  messagingSenderId: process.env.FIREBASE_WEB_MESSAGING_SENDER_ID || "",
  appId: process.env.FIREBASE_WEB_APP_ID || "",
  measurementId: process.env.FIREBASE_WEB_MEASUREMENT_ID || ""
};

const store = new DataStore({
  lowBatteryThreshold: Number(process.env.LOW_BATTERY_THRESHOLD || 25),
  highAttackThreshold: Number(process.env.HIGH_ATTACK_THRESHOLD || 80),
  telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || "",
  telegramChatId: process.env.TELEGRAM_CHAT_ID || ""
});

app.disable("x-powered-by");

app.use((req, res, next) => {
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "frame-src 'self' https: http:",
      "img-src 'self' data: https: http:",
      "media-src 'self' data: https: http: blob:",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' https://www.gstatic.com",
      "connect-src 'self' https://www.gstatic.com https://*.firebaseio.com https://*.firebasedatabase.app https://firebasestorage.googleapis.com https://securetoken.googleapis.com https://identitytoolkit.googleapis.com https://www.googleapis.com",
      "font-src 'self' data:"
    ].join("; ")
  );
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

function hashText(value) {
  return crypto.createHash("sha256").update(String(value)).digest();
}

function safeCompare(left, right) {
  if (!left || !right) {
    return false;
  }

  return crypto.timingSafeEqual(hashText(left), hashText(right));
}

function parseCookies(req) {
  const rawCookies = req.headers.cookie || "";
  return rawCookies.split(";").reduce((accumulator, segment) => {
    const [key, ...rest] = segment.trim().split("=");
    if (!key) {
      return accumulator;
    }

    accumulator[key] = decodeURIComponent(rest.join("="));
    return accumulator;
  }, {});
}

function signSessionPayload(encodedPayload) {
  return crypto.createHmac("sha256", sessionSecret).update(encodedPayload).digest("base64url");
}

function createSessionToken() {
  const payload = {
    sub: "authorized-authority",
    exp: Date.now() + sessionTtlMs,
    nonce: crypto.randomUUID()
  };
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encodedPayload}.${signSessionPayload(encodedPayload)}`;
}

function verifySessionToken(token) {
  if (!token || !token.includes(".")) {
    return false;
  }

  const [encodedPayload, signature] = token.split(".");
  const expectedSignature = signSessionPayload(encodedPayload);

  if (!safeCompare(signature, expectedSignature)) {
    return false;
  }

  try {
    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    return payload.exp > Date.now();
  } catch {
    return false;
  }
}

function buildCookie(value, maxAgeMs = sessionTtlMs) {
  const parts = [
    `${cookieName}=${encodeURIComponent(value)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Strict",
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`
  ];

  if (isProduction) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function clearCookie() {
  return `${cookieName}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0${isProduction ? "; Secure" : ""}`;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    return String(forwarded).split(",")[0].trim();
  }

  return req.socket.remoteAddress || "unknown";
}

function isRateLimited(ipAddress) {
  if (!isProduction) {
    return false;
  }

  const cutoff = Date.now() - loginWindowMs;
  const recentAttempts = (loginAttempts.get(ipAddress) || []).filter((timestamp) => timestamp > cutoff);
  loginAttempts.set(ipAddress, recentAttempts);
  return recentAttempts.length >= maxFailedLogins;
}

function recordFailedLogin(ipAddress) {
  if (!isProduction) {
    return;
  }

  const attempts = loginAttempts.get(ipAddress) || [];
  attempts.push(Date.now());
  loginAttempts.set(ipAddress, attempts);
}

function clearFailedLogins(ipAddress) {
  loginAttempts.delete(ipAddress);
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  if (!verifySessionToken(cookies[cookieName])) {
    res.status(401).json({ error: "Authentication required." });
    return;
  }

  next();
}

function requireDeviceToken(req, res, next) {
  if (!ingestToken) {
    next();
    return;
  }

  const providedToken =
    req.headers["x-device-token"] ||
    req.headers.authorization?.replace(/^Bearer\s+/i, "") ||
    req.body?.token;

  if (!providedToken || !safeCompare(providedToken, ingestToken)) {
    res.status(401).json({ error: "Invalid device token." });
    return;
  }

  next();
}

function sendSseEvent(res, eventName, payload) {
  res.write(`event: ${eventName}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

app.get("/health", async (req, res) => {
  res.json({
    ok: true,
    realtime: true,
    firebaseEnabled: store.firebaseEnabled,
    timestamp: new Date().toISOString()
  });
});

app.get("/api/auth/session", requireAuth, (req, res) => {
  res.json({ authenticated: true });
});

app.get("/api/firebase-config", requireAuth, (req, res) => {
  const enabled = Boolean(
    firebaseWebConfig.apiKey &&
      firebaseWebConfig.projectId &&
      firebaseWebConfig.databaseURL &&
      firebaseWebConfig.appId
  );

  res.json({
    enabled,
    config: enabled ? firebaseWebConfig : null
  });
});

app.post("/api/auth/login", (req, res) => {
  const { secret } = req.body || {};
  const ipAddress = getClientIp(req);

  if (!secret) {
    res.status(400).json({ error: "PIN or password is required." });
    return;
  }

  if (isRateLimited(ipAddress)) {
    res.status(429).json({ error: "Too many failed attempts. Please try again later." });
    return;
  }

  const validSecret = [authPassword, authPin].some((candidate) => candidate && safeCompare(secret, candidate));

  if (!validSecret) {
    recordFailedLogin(ipAddress);
    res.status(401).json({ error: "Invalid credentials." });
    return;
  }

  clearFailedLogins(ipAddress);
  res.setHeader("Set-Cookie", buildCookie(createSessionToken()));
  res.json({ authenticated: true });
});

app.post("/api/auth/logout", (req, res) => {
  res.setHeader("Set-Cookie", clearCookie());
  res.json({ authenticated: false });
});

app.get("/api/dashboard", requireAuth, async (req, res, next) => {
  try {
    res.json(await store.getDashboardSnapshot());
  } catch (error) {
    next(error);
  }
});

app.get("/api/stream", requireAuth, async (req, res, next) => {
  try {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    const publishSnapshot = async () => {
      sendSseEvent(res, "snapshot", await store.getDashboardSnapshot());
    };

    await publishSnapshot();

    const unsubscribe = store.subscribe(async () => {
      try {
        await publishSnapshot();
      } catch (error) {
        console.error("Unable to publish SSE snapshot:", error.message);
      }
    });

    const heartbeat = setInterval(() => {
      sendSseEvent(res, "ping", { timestamp: Date.now() });
    }, 30000);

    req.on("close", () => {
      clearInterval(heartbeat);
      unsubscribe();
      res.end();
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/robot/capture", requireAuth, async (req, res, next) => {
  if (!esp32CaptureUrl) {
    res.status(503).json({ error: "ESP32_CAM_CAPTURE_URL is not configured." });
    return;
  }

  try {
    const response = await fetch(esp32CaptureUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(esp32SharedSecret ? { "x-shared-secret": esp32SharedSecret } : {})
      },
      body: JSON.stringify({ requestedAt: new Date().toISOString() }),
      signal: AbortSignal.timeout(10000)
    });

    if (!response.ok) {
      throw new Error(`ESP32-CAM responded with ${response.status}`);
    }

    const contentType = response.headers.get("content-type") || "";
    const payload = contentType.includes("application/json") ? await response.json() : {};
    const imageUrl = payload.imageUrl || payload.url || null;

    await store.createAlert({
      message: imageUrl ? "Manual capture completed." : "Manual capture requested.",
      severity: "normal",
      alertType: "manual-capture"
    });

    if (imageUrl) {
      await store.addImage({
        url: imageUrl,
        caption: "Manual security capture",
        alertType: "manual-capture"
      });
    }

    res.json({
      ok: true,
      imageUrl,
      message: imageUrl ? "Manual capture completed." : "Capture request sent."
    });
  } catch (error) {
    await store.createAlert({
      message: `Manual capture failed: ${error.message}`,
      severity: "warning",
      alertType: "manual-capture"
    });
    next(error);
  }
});

app.post("/api/ingest/telemetry", requireDeviceToken, async (req, res, next) => {
  try {
    const result = await store.ingestTelemetry(req.body || {});
    res.status(202).json(result);
  } catch (error) {
    next(error);
  }
});

app.post("/api/ingest/alert", requireDeviceToken, async (req, res, next) => {
  try {
    const alert = await store.createAlert({
      message: req.body?.message || "Security alert received.",
      severity: req.body?.severity || req.body?.type || "warning",
      alertType: req.body?.alertType || "system",
      imageUrl: req.body?.imageUrl || null,
      metadata: req.body?.metadata || {}
    });
    res.status(201).json({ ok: true, alert });
  } catch (error) {
    next(error);
  }
});

app.post("/api/ingest/image", requireDeviceToken, async (req, res, next) => {
  try {
    const image = await store.addImage({
      url: req.body?.url || req.body?.imageUrl,
      caption: req.body?.caption || "ESP32-CAM capture",
      alertType: req.body?.alertType || "intruder"
    });
    res.status(201).json({ ok: true, image });
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => {
  if (req.path.startsWith("/api/")) {
    res.status(404).json({ error: "API route not found." });
    return;
  }

  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((error, req, res, next) => {
  console.error(error);
  const statusCode = error.statusCode || 500;
  res.status(statusCode).json({
    error: statusCode === 500 ? "Internal server error." : error.message
  });
});

async function startServer() {
  await store.init();

  app.listen(port, () => {
    console.log(`Smart security dashboard listening on http://localhost:${port}`);

    if (!authPassword && !authPin) {
      console.warn("No AUTH_PASSWORD or AUTH_PIN set. Configure credentials before deployment.");
    }

    if (!ingestToken) {
      console.warn("DEVICE_INGEST_TOKEN is not configured. Device ingest endpoints are open for local development.");
    }
  });
}

startServer().catch((error) => {
  console.error("Unable to start server:", error);
  process.exit(1);
});
