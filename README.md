# Smart Security Robot Dashboard

Secure Express + Firebase-ready monitoring dashboard for a smart security robot and ESP32-CAM alert pipeline.

## Included Features

- Login screen with PIN/password authentication and signed HttpOnly session cookie
- Dark, mobile-friendly security operations dashboard
- Real-time updates without page refresh using protected Server-Sent Events
- Robot telemetry panel with online/offline state, battery level, attack score, and last sync
- Alerts feed with timestamps and severity states: normal, warning, critical
- Image gallery for ESP32-CAM captures and intruder photos
- Manual camera capture trigger endpoint for ESP32-CAM
- Optional Telegram notifications for critical alerts
- Firestore persistence support with local in-memory fallback for development
- Firebase Realtime Database website listeners for `/robot/control`, `/robot/mode`, `/robot/images`, `/robot/alert`, `/robot/logs`, `/robot/battery`, `/robot/motion`, and `/robot/stream`

## Quick Start

1. Install dependencies:

```bash
npm install
```

2. Copy the environment example and set your values:

```bash
copy .env.example .env
```

3. Start the app:

```bash
npm start
```

4. Open `http://localhost:3000`

## Environment Variables

Use `.env.example` as the template.

- `AUTH_PASSWORD` and/or `AUTH_PIN`: login secret for authorized authorities
- `SESSION_SECRET`: secret used to sign login sessions
- `DEVICE_INGEST_TOKEN`: shared token required by ESP32 or sensor clients
- `ESP32_CAM_CAPTURE_URL`: endpoint hit when the dashboard requests a manual capture
- `ESP32_CAM_SHARED_SECRET`: optional shared secret forwarded to the ESP32-CAM
- `LOW_BATTERY_THRESHOLD`: battery warning threshold
- `HIGH_ATTACK_THRESHOLD`: score threshold for high attack alerts
- `FIREBASE_SERVICE_ACCOUNT_JSON`: Firebase Admin service account JSON on one line
- `FIREBASE_STORAGE_BUCKET`: storage bucket name if you use Firebase Storage
- `FIREBASE_WEB_*`: public Firebase web configuration used by the dashboard to subscribe to Realtime Database paths
- `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`: optional Telegram alert delivery

## Firestore Collections

If Firebase is configured, the app writes to:

- `robots/main`
- `alerts/{alertId}`
- `images/{imageId}`

## ESP32 / Sensor Integration

### 1. Telemetry and automatic alerts

Send HTTP POST requests to `/api/ingest/telemetry`.

Example payload:

```json
{
  "online": true,
  "statusText": "Patrolling sector A",
  "batteryLevel": 22,
  "attackScore": 91,
  "motionDetected": true,
  "intruderDetected": true,
  "multipleDetections": true,
  "imageUrl": "https://your-storage.example/intruder-001.jpg",
  "source": "esp32-cam"
}
```

Headers:

```http
Content-Type: application/json
x-device-token: YOUR_DEVICE_INGEST_TOKEN
```

### 2. Direct custom alert

Send POST to `/api/ingest/alert`.

```json
{
  "message": "Sudden shock detected on left-side sensor.",
  "severity": "critical",
  "alertType": "high-attack"
}
```

### 3. Direct image upload URL registration

Send POST to `/api/ingest/image`.

```json
{
  "imageUrl": "https://your-storage.example/frame-002.jpg",
  "caption": "Motion-triggered capture",
  "alertType": "motion"
}
```

## Notes

- The server uses an in-memory store until Firebase credentials are configured.
- Image files themselves are not uploaded by this app. Store them in Firebase Storage or another storage target, then send the resulting public or signed URL to the dashboard.
- For production deployment, set strong secrets, enable HTTPS, and keep `DEVICE_INGEST_TOKEN` configured.
