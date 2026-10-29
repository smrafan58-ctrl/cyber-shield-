# CyberShield AI — Firestore Zero-Trust Security Specification (Phase 0 & Phase 5 Audit)

## 1. Data Invariants & Relational Mapping
1. **Default Deny Catch-All**: Every path not explicitly matched under `/databases/{database}/documents` is unconditionally denied (`allow read, write: if false;`).
2. **User Profile Ownership (`/users/{userId}`)**:
   - A `UserProfile` document can only be read (`get`), created, or updated by the authenticated user whose `request.auth.uid == userId` and `request.auth.token.email_verified == true` (for writes).
   - `list` and `delete` operations on `/users/{userId}` are unconditionally forbidden (`allow list, delete: if false;`) to prevent user enumeration and PII scraping.
   - `uid` and `createdAt` are immutable once created (`incoming().uid == existing().uid && incoming().createdAt == existing().createdAt`).
   - All timestamps (`createdAt`, `updatedAt`) must equal `request.time`.
3. **Scan Record Ownership & Parent Existence (`/scans/{scanId}`)**:
   - A `ScanRecord` cannot be created unless the owner's `/users/{userId}` document already exists (`exists(/databases/$(database)/documents/users/$(incoming().userId))`).
   - `incoming().userId` must strictly equal `request.auth.uid`, and `incoming().id` must strictly equal `scanId`.
   - `allow list` on `/scans/{scanId}` enforces `isSignedIn() && resource.data.userId == request.auth.uid` with zero `get()`/`exists()` calls inside `list` (preventing O(n) cost explosions and unauthorized cross-user query scraping).
   - `userId`, `id`, and `createdAt` are immutable across updates.

---

## 2. The "Dirty Dozen" Adversarial Payloads

| # | Attack Vector | Target Path | Malicious Payload / Operation | Expected Result |
|---|---------------|-------------|-------------------------------|-----------------|
| 1 | **Identity Spoofing (User Profile)** | `CREATE /users/victim_uid` (Auth: `attacker_uid`) | `{ uid: "victim_uid", displayName: "Spoof", photoURL: "", scanCount: 0, createdAt: request.time, updatedAt: request.time }` | `PERMISSION_DENIED` |
| 2 | **Unverified Email Write** | `CREATE /users/attacker_uid` (`email_verified: false`) | Valid `UserProfile` payload with unverified email token | `PERMISSION_DENIED` |
| 3 | **Shadow Field Injection (User Profile)** | `UPDATE /users/user_1` | `{ ..., isAdmin: true, role: "superuser" }` | `PERMISSION_DENIED` (`hasOnly` blocks ghost keys) |
| 4 | **User Enumeration / Blanket List** | `LIST /users` | Authenticated user queries `collection(db, 'users')` | `PERMISSION_DENIED` (`allow list: if false`) |
| 5 | **Timestamp Forgery (Backdating)** | `CREATE /scans/scan_1` | `createdAt: Timestamp.fromMillis(1600000000000)` instead of `request.time` | `PERMISSION_DENIED` |
| 6 | **Orphaned Scan Record Write** | `CREATE /scans/scan_1` | Authenticated user with no `/users/{uid}` profile attempts to create a scan | `PERMISSION_DENIED` (`exists()` check fails) |
| 7 | **Cross-Tenant Scan Creation** | `CREATE /scans/scan_1` (Auth: `user_A`) | `{ id: "scan_1", userId: "user_B", ... }` | `PERMISSION_DENIED` (`data.userId == request.auth.uid` fails) |
| 8 | **Cross-Tenant List Scraping** | `LIST /scans` (Auth: `user_A`) | Query without `where('userId', '==', 'user_A')` | `PERMISSION_DENIED` (`resource.data.userId == request.auth.uid` fails) |
| 9 | **ID Poisoning / Oversized Path ID** | `CREATE /scans/{200_char_junk_id}` | Document ID exceeds 128 chars or contains illegal characters | `PERMISSION_DENIED` (`isValidId(scanId)` fails) |
| 10 | **Denial-of-Wallet String Bloat** | `CREATE /scans/scan_1` | `summaryExplanation` contains a 50,000-character string | `PERMISSION_DENIED` (`size() <= 1000` fails) |
| 11 | **Array Poisoning** | `CREATE /scans/scan_1` | `indicatorNames` contains 50 items or non-string first element `[12345]` | `PERMISSION_DENIED` (`size() <= 20` and type check fail) |
| 12 | **Immutable Field Mutation** | `UPDATE /scans/scan_1` | Mutating `userId` or `createdAt` during an update | `PERMISSION_DENIED` |

---

## 3. Security Rules Test Runner Specification (`firestore.rules.test.ts`)

```typescript
// Specification for verifying all 12 Dirty Dozen payloads against firestore.rules:
// 1. Spoofed UID on /users/{userId} -> assertFails
// 2. Unverified email token on /users/{userId} -> assertFails
// 3. Shadow field (isAdmin: true) on /users/{userId} -> assertFails
// 4. Listing /users collection -> assertFails
// 5. Client-forged timestamp (createdAt != request.time) -> assertFails
// 6. Creating /scans/{scanId} before /users/{userId} exists -> assertFails
// 7. Creating /scans/{scanId} with userId != auth.uid -> assertFails
// 8. Listing /scans without matching userId filter -> assertFails
// 9. Document ID with invalid regex or length > 128 -> assertFails
// 10. Oversized summaryExplanation (> 1000 chars) -> assertFails
// 11. Oversized indicatorNames array (> 20 items) or non-string element -> assertFails
// 12. Mutating immutable createdAt or userId on update -> assertFails
```

---

## 4. Phase 5 Red Team Conflict Report

- **Collection `/users/{userId}`**:
  - *Identity Spoofing*: Blocked (`request.auth.uid == userId && data.uid == request.auth.uid`).
  - *Shadow Update Test*: Blocked (`hasOnly(['uid', 'displayName', 'photoURL', 'scanCount', 'createdAt', 'updatedAt'])` + `affectedKeys().hasOnly(...)`).
  - *Email Spoofing Test*: Blocked (`request.auth.token.email_verified == true` required on all writes).
  - *PII Blanket Test*: Blocked (`allow get: if isSignedIn() && isValidId(userId) && request.auth.uid == userId; allow list: if false;`).
  - *Value Poisoning Test*: Blocked (`isValidUserProfile(incoming())` wraps `allow update`).
- **Collection `/scans/{scanId}`**:
  - *Identity Spoofing*: Blocked (`data.userId == request.auth.uid` and `existing().userId == request.auth.uid`).
  - *Shadow Update Test*: Blocked (`hasOnly` on all 19 required keys and `affectedKeys().hasOnly(...)` on update).
  - *Query Trust Test*: Passed (`allow list: if isSignedIn() && resource.data.userId == request.auth.uid;` with zero `get()` calls).
  - *Value Poisoning Test*: Blocked (`isValidScanRecord(incoming())` wraps `allow update`).
