import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signOut,
  User,
} from 'firebase/auth';
import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocFromServer,
  getDocs,
  getFirestore,
  limit,
  onSnapshot,
  query,
  serverTimestamp,
  setDoc,
  Timestamp,
  Unsubscribe,
  updateDoc,
  where,
} from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';
import { MANDATORY_DISCLAIMER } from './engine/constants';
import {
  DetectedIndicator,
  RecommendedGuidance,
  RiskClassification,
  URLAnalysisResult,
} from './types/scanner';

// Initialize Firebase App, Auth, and Firestore
const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

// Validate connection to Firestore on boot
async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes('the client is offline')
    ) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
testConnection();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// Validation constants synchronized verbatim with firebase-blueprint.json & firestore.rules
const SAFE_ID_PATTERN = /^[a-zA-Z0-9_\-]+$/;

function clampString(val: string | undefined | null, fallback: string, maxLen: number): string {
  const cleaned = (val ?? '').trim();
  const nonEmpty = cleaned.length > 0 ? cleaned : fallback;
  return nonEmpty.slice(0, maxLen);
}

function toSafeFirestoreId(raw: string): string {
  const sanitized = raw.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 120);
  if (sanitized.length > 0 && SAFE_ID_PATTERN.test(sanitized)) {
    return sanitized;
  }
  return `scan_${Date.now()}`;
}

export function buildDeterministicScanDocId(userId: string, normalizedUrl: string): string {
  let hash = 2166136261;
  for (let i = 0; i < normalizedUrl.length; i++) {
    hash ^= normalizedUrl.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const unsignedHash = (hash >>> 0).toString(16);
  const safeUid = toSafeFirestoreId(userId).slice(0, 64);
  return `${safeUid}_${unsignedHash}`;
}

function buildDefaultGuidanceForClassification(
  classification: RiskClassification
): RecommendedGuidance {
  const universalRules = [
    'Do not enter passwords on suspicious sites.',
    'Never share OTPs or banking credentials.',
    "Do not pay fines or transfer money based solely on a link's claims.",
    'Access official services through independently verified websites or applications.',
  ];

  switch (classification) {
    case 'LOW RISK INDICATORS':
      return {
        headline: 'Low Observable Structural Risk',
        primaryAdvice:
          'No high-risk structural anomalies were detected in the URL string. Still verify you are on the expected domain before signing in.',
        universalRules,
      };
    case 'MILD SUSPICION':
      return {
        headline: 'Inspect Destination Carefully',
        primaryAdvice:
          'This link has minor structural warning signs. Confirm you recognize the domain before interacting with forms or downloads.',
        universalRules,
      };
    case 'MODERATE RISK':
      return {
        headline: 'Proceed With Elevated Caution',
        primaryAdvice:
          'Multiple suspicious URL characteristics were found. Avoid entering sensitive information and navigate to the service directly instead.',
        universalRules,
      };
    case 'HIGH RISK':
      return {
        headline: 'High Phishing / Deception Risk — Avoid Clicking',
        primaryAdvice:
          'This URL exhibits strong indicators of domain spoofing or credential harvesting. Close the link and access the organization via a trusted bookmark.',
        universalRules,
      };
    case 'VERY HIGH RISK':
      return {
        headline: 'Critical Threat Indicators — Do Not Open',
        primaryAdvice:
          'Severe deceptive patterns detected. Do not open this link, do not submit any data, and report the message to your security team.',
        universalRules,
      };
  }
}

export async function signInWithGooglePopup(): Promise<User> {
  const credential = await signInWithPopup(auth, googleProvider);
  await ensureUserProfileDocument(credential.user);
  return credential.user;
}

export async function signOutUser(): Promise<void> {
  await signOut(auth);
}

export async function ensureUserProfileDocument(user: User): Promise<void> {
  if (!user?.uid || !SAFE_ID_PATTERN.test(user.uid)) return;
  const userPath = `users/${user.uid}`;
  const userRef = doc(db, 'users', user.uid);

  let snap;
  try {
    snap = await getDoc(userRef);
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, userPath);
  }

  const displayName = clampString(
    user.displayName || user.email?.split('@')[0],
    'CyberShield Analyst',
    120
  );
  const photoURL = (user.photoURL ?? '').trim().slice(0, 1024);

  if (!snap.exists()) {
    try {
      await setDoc(userRef, {
        uid: user.uid,
        displayName,
        photoURL,
        scanCount: 0,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, userPath);
    }
  } else {
    const existingData = snap.data();
    const currentCount =
      typeof existingData?.scanCount === 'number' && existingData.scanCount >= 0
        ? Math.min(100000, Math.floor(existingData.scanCount))
        : 0;
    try {
      await updateDoc(userRef, {
        displayName,
        photoURL,
        scanCount: currentCount,
        updatedAt: serverTimestamp(),
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, userPath);
    }
  }
}

export async function saveScanToFirestore(
  user: User,
  result: URLAnalysisResult
): Promise<void> {
  if (!user?.uid || !SAFE_ID_PATTERN.test(user.uid)) return;

  await ensureUserProfileDocument(user);

  const scanId = buildDeterministicScanDocId(
    user.uid,
    result.domain.normalizedUrl || result.domain.redactedUrl
  );
  const scanPath = `scans/${scanId}`;
  const scanRef = doc(db, 'scans', scanId);

  let existingSnap;
  try {
    existingSnap = await getDoc(scanRef);
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, scanPath);
  }

  const protocol: 'HTTP' | 'HTTPS' =
    result.domain.protocol === 'HTTP' ? 'HTTP' : 'HTTPS';

  const indicatorNames = result.indicators
    .slice(0, 20)
    .map((ind) => clampString(ind.name, 'Heuristic Indicator', 200));

  const commonFields = {
    normalizedUrl: clampString(
      result.domain.normalizedUrl,
      result.domain.redactedUrl || 'https://example.com/',
      2048
    ),
    redactedUrl: clampString(
      result.domain.redactedUrl,
      result.domain.normalizedUrl || 'https://example.com/',
      2048
    ),
    hostname: clampString(result.domain.hostname, 'example.com', 255),
    registrableDomain: clampString(
      result.domain.registrableDomain,
      result.domain.hostname || 'example.com',
      255
    ),
    subdomain: clampString(result.domain.subdomain, 'None', 255),
    tld: clampString(result.domain.tld, 'com', 64),
    protocol,
    port: clampString(result.domain.port, 'Default', 32),
    path: clampString(result.domain.path, '/', 1024),
    urlLength: Math.max(1, Math.min(4096, Math.floor(result.domain.urlLength || 1))),
    queryParamCount: Math.max(
      0,
      Math.min(200, Math.floor(result.domain.queryParamCount || 0))
    ),
    riskScore: Math.max(0, Math.min(100, Math.floor(result.riskScore || 0))),
    classification: result.classification,
    summaryExplanation: clampString(
      result.summaryExplanation,
      'Deterministic static URL inspection completed.',
      1000
    ),
    indicatorNames,
    updatedAt: serverTimestamp(),
  };

  if (!existingSnap.exists()) {
    try {
      await setDoc(scanRef, {
        id: scanId,
        userId: user.uid,
        ...commonFields,
        createdAt: serverTimestamp(),
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.CREATE, scanPath);
    }
  } else {
    try {
      await updateDoc(scanRef, commonFields);
    } catch (error) {
      handleFirestoreError(error, OperationType.UPDATE, scanPath);
    }
  }
}

export async function deleteAllUserScansFromFirestore(user: User): Promise<void> {
  if (!user?.uid) return;
  const scansQuery = query(
    collection(db, 'scans'),
    where('userId', '==', user.uid),
    limit(50)
  );

  let snapshot;
  try {
    snapshot = await getDocs(scansQuery);
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, 'scans');
  }

  for (const docSnap of snapshot.docs) {
    try {
      await deleteDoc(doc(db, 'scans', docSnap.id));
    } catch (error) {
      handleFirestoreError(error, OperationType.DELETE, `scans/${docSnap.id}`);
    }
  }
}

function hydrateScanRecordToAnalysisResult(
  docId: string,
  data: Record<string, unknown>
): URLAnalysisResult {
  const classification = (data.classification as RiskClassification) || 'LOW RISK INDICATORS';
  const indicatorNames = Array.isArray(data.indicatorNames)
    ? (data.indicatorNames as string[])
    : [];

  const indicators: DetectedIndicator[] = indicatorNames.map((name, idx) => ({
    id: `cloud-ind-${idx}`,
    name: String(name),
    severity: 'Medium',
    weight: 10,
    explanation: `Triggered heuristic indicator recorded during scan: ${String(name)}.`,
    component: String(data.hostname || ''),
    reasonItMatters:
      'Review the full URL structure and domain ownership before interacting with this link.',
  }));

  const updatedAtVal = data.updatedAt as Timestamp | undefined;
  const isoTimestamp =
    updatedAtVal && typeof updatedAtVal.toDate === 'function'
      ? updatedAtVal.toDate().toISOString()
      : new Date().toISOString();

  const hostname = String(data.hostname || 'example.com');
  const normalizedUrl = String(data.normalizedUrl || 'https://example.com/');
  const redactedUrl = String(data.redactedUrl || normalizedUrl);

  return {
    id: String(data.id || docId),
    timestamp: isoTimestamp,
    riskScore: typeof data.riskScore === 'number' ? data.riskScore : 0,
    classification,
    summaryExplanation: String(
      data.summaryExplanation || 'Static URL analysis record loaded from Firestore.'
    ),
    disclaimer: MANDATORY_DISCLAIMER,
    domain: {
      originalInput: redactedUrl,
      normalizedUrl,
      redactedUrl,
      protocol: String(data.protocol || 'HTTPS'),
      hostname,
      registrableDomain: String(data.registrableDomain || hostname),
      subdomain: String(data.subdomain || 'None'),
      tld: String(data.tld || 'com'),
      port: String(data.port || 'Default'),
      path: String(data.path || '/'),
      urlLength: typeof data.urlLength === 'number' ? data.urlLength : redactedUrl.length,
      hostnameLength: hostname.length,
      queryParamCount:
        typeof data.queryParamCount === 'number' ? data.queryParamCount : 0,
      queryParamKeys: [],
      hasCredentialsInAuthority: false,
      isIpAddress: data.tld === 'IP Literal',
      isPunycode: hostname.includes('xn--'),
    },
    indicators,
    reputation: {
      checked: false,
      status: 'not_configured',
      summaryLabel: 'Local URL heuristic analysis — external reputation not checked.',
      providerName: 'Local Engine Only',
      lastCheckedAt: null,
    },
    guidance: buildDefaultGuidanceForClassification(classification),
  };
}

export function subscribeToUserScans(
  user: User,
  onScansUpdated: (scans: URLAnalysisResult[]) => void,
  onErrorCallback?: (err: Error) => void
): Unsubscribe {
  const scansQuery = query(
    collection(db, 'scans'),
    where('userId', '==', user.uid),
    limit(25)
  );

  return onSnapshot(
    scansQuery,
    (snapshot) => {
      const recordsWithTime = snapshot.docs.map((docSnap) => {
        const raw = docSnap.data();
        const updatedAt = raw.updatedAt as Timestamp | undefined;
        const millis =
          updatedAt && typeof updatedAt.toMillis === 'function'
            ? updatedAt.toMillis()
            : 0;
        return {
          millis,
          result: hydrateScanRecordToAnalysisResult(docSnap.id, raw),
        };
      });

      recordsWithTime.sort((a, b) => b.millis - a.millis);
      onScansUpdated(recordsWithTime.slice(0, 5).map((item) => item.result));
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, 'scans');
      } catch (handledErr) {
        if (onErrorCallback && handledErr instanceof Error) {
          onErrorCallback(handledErr);
        }
      }
    }
  );
}
