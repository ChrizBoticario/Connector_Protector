// =============================================================================
// ConnectProtect — Unified Edge-AI Detection Engine (engine.js)
// Version 2.2 — Single source of truth for all URL analysis logic.
// Used by both content.js (Speed Bump) and popup.js (Manual Scan).
// =============================================================================

'use strict';

// ---------------------------------------------------------------------------
// CONFIGURATION
// ---------------------------------------------------------------------------

/**
 * Protected brand targets for Levenshtein typosquatting detection.
 * Includes Philippine financial institutions + global high-value targets.
 */
const CP_TARGETS = [
    // Philippine Financial
    'bdo.com.ph', 'gcash.com', 'bpi.com.ph', 'metrobank.com.ph',
    'unionbankph.com', 'maya.ph', 'landbank.com', 'pnb.com.ph',
    // Global Financial
    'paypal.com', 'wise.com', 'stripe.com',
    // Global High-Value
    'facebook.com', 'google.com', 'apple.com', 'microsoft.com',
    'amazon.com', 'netflix.com', 'instagram.com', 'twitter.com',
    'linkedin.com', 'github.com',
];

/**
 * Global whitelist — domains that bypass AI scanning entirely.
 */
const CP_GLOBAL_WHITELIST = [
    // --- User Safe URLs ---
    'facebook.com',
    'youtube.com',
    'whatsapp.com',
    'instagram.com',
    'tiktok.com',
    'wechat.com',
    'telegram.org', // note: web.telegram.org -> telegram.org
    'snapchat.com',
    'reddit.com',
    'kuaishou.com',
    'x.com',
    'linkedin.com',
    'weibo.com',
    'pinterest.com',
    'qq.com',
    'discord.com',
    'tumblr.com',
    'quora.com',
    'twitch.tv',
    'vimeo.com',
    
    // --- Search Engines & AI ---
    'google.com', 'google.com.ph', 'bing.com', 'yahoo.com', 'yandex.ru', 'duckduckgo.com',
    'chatgpt.com', 'openai.com',
    
    // --- Tech & Shopping ---
    'microsoft.com', 'apple.com', 'amazon.com', 'temu.com', 'github.com', 'zoom.us',
    
    // --- Reference & Education ---
    'wikipedia.org', 'wikimedia.org', 'instructure.com',
    
    // --- Philippine Banks ---
    'bdo.com.ph', 'bpi.com.ph', 'gcash.com', 'maya.ph', 'metrobank.com.ph', 'unionbankph.com',
];

/**
 * Suspicious top-level domains associated with free/abuse-prone registrars.
 */
const CP_SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.pw', '.click', '.loan', '.win', '.men', '.work',
    '.stream', '.download', '.racing', '.party', '.review',
    '.science', '.accountant', '.faith', '.date', '.bid',
];

/**
 * Brand name keywords — if found in a hostname that is NOT the brand's own
 * registered domain, it signals brand impersonation.
 */
const CP_BRAND_KEYWORDS = [
    'paypal', 'gcash', 'bdo', 'bpi', 'metrobank', 'unionbank', 'maya', 'landbank',
    'facebook', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'instagram',
    'twitter', 'linkedin', 'github', 'stripe', 'wise', 'yahoo', 'wiki',
    'citibank', 'hsbc', 'visa', 'mastercard', 'coinbase', 'binance',
];

/**
 * Path keywords strongly associated with phishing pages.
 */
const CP_SUSPICIOUS_PATH_KEYWORDS = [
    'login', 'signin', 'sign-in', 'logon',
    'verify', 'verification', 'validate', 'authenticate',
    'account', 'myaccount', 'update', 'confirm',
    'secure', 'security', 'reset', 'password', 'recover',
    'banking', 'wallet', 'billing', 'payment', 'checkout',
    'webscr', 'component/user',
];

/** Path patterns used to redirect victims to attacker-controlled URLs. */
const CP_REDIRECT_PATTERNS = ['/redirect/', '/go/', '/out/', '/click/', '/track/'];

/** Informational or safe keywords in the path that reduce risk score. */
const CP_SAFE_PATH_KEYWORDS = ['contact', 'contact-us', 'contact.us', 'contactus', 'learn', 'learn-more', 'learn_more', 'report', 'about', 'help', 'support', 'privacy', 'terms', 'faq'];

/**
 * Edge model threshold.
 * Scores 1-35 are shown as SAFE. Scores 36-99 are shown as HIGH RISK.
 */
const CP_RISK_THRESHOLD = 36;
const CP_NO_HTTPS_RISK_FLOOR = 90;
const CP_EDGE_AI_MODEL = {
    id: 'CP-EDGE-LIN-2.2',
    version: '2.2',
    type: 'local weighted linear classifier',
    threshold: CP_RISK_THRESHOLD,
    bias: -4.25,
    weights: {
        noHttps: 1.40,
        length: 0.80,
        subdomainDepth: 1.10,
        entropy: 0.90,
        levenshteinSimilarity: 2.40,
        ipAddress: 2.40,
        suspiciousTld: 1.20,
        punycode: 1.80,
        atSign: 2.00,
        excessiveHyphens: 0.80,
        numericSubdomain: 0.80,
        longSubdomain: 0.70,
        numericMainDomain: 1.20,
        brandKeywordInHost: 2.20,
        suspiciousPathKeyword: 1.40,
        redirectPattern: 1.20,
        manyPathSegments: 0.60,
        safePathKeyword: -1.00,
    },
    featureOrder: [
        'noHttps',
        'length',
        'subdomainDepth',
        'entropy',
        'levenshteinSimilarity',
        'ipAddress',
        'suspiciousTld',
        'punycode',
        'atSign',
        'excessiveHyphens',
        'numericSubdomain',
        'longSubdomain',
        'numericMainDomain',
        'brandKeywordInHost',
        'suspiciousPathKeyword',
        'redirectPattern',
        'manyPathSegments',
        'safePathKeyword',
    ],
};
/**
 * Extracts a wrapped URL from query parameters
 * @param {string} rawUrl 
 * @returns {string}
 */
// Function: cp_extractWrappedURL
// - Inputs: rawUrl (string).
// - Step 1: Cleans input URL by trimming leading/trailing whitespace.
// - Step 2: Enforces protocol by prepending 'https://' if missing.
// - Step 3: Parses the URL string into an object representation.
// - Step 4: Iterates through search query parameters to find embedded helper URLs.
// - Step 5: Extracts and returns the wrapped URL if detected, otherwise returns rawUrl.
function cp_extractWrappedURL(rawUrl) {
    try {
        let url = rawUrl.trim();
        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
        const urlObj = new URL(url);
        for (const [key, value] of urlObj.searchParams.entries()) {
            if (/^https?:\/\//i.test(value)) {
                return value;
            }
        }
    } catch (e) {}
    return rawUrl;
}

/**
 * Normalizes leet-speak / homoglyph digit substitutions in a hostname
 * so typosquatting like paypa1, go0gle, micr0soft are caught by Levenshtein.
 * @param {string} hostname
 * @returns {string}
 */
// Function: cp_normalizeLeet
// - Inputs: hostname (string).
// - Step 1: Targets and translates homoglyphs/leet-speak patterns back to normal characters (e.g. '0'->'o', '1'->'l').
// - Step 2: Normalizes symbols like '$' to 's'.
// - Step 3: Returns the clean, standardized alphabetical hostname.
function cp_normalizeLeet(hostname) {
    return hostname
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/3/g, 'e')
        .replace(/4/g, 'a')
        .replace(/5/g, 's')
        .replace(/6/g, 'b')
        .replace(/8/g, 'b')
        .replace(/\$/g, 's');
}

/**
 * Normalizes a URL to a clean lowercase hostname+path string for analysis.
 * Strips protocol, www prefix, query strings, and trailing slashes.
 * @param {string} rawUrl
 * @returns {string}
 */
// Function: cp_normalizeURL
// - Inputs: rawUrl (string).
// - Step 1: Strips leading/trailing white space from the raw URL.
// - Step 2: Ensures a valid protocol prefix exists before parsing.
// - Step 3: Parses using the URL constructor and removes the "www." subdomain prefix.
// - Step 4: Appends query search string onto pathname to preserve full payload detail.
// - Step 5: Removes trailing slashes and converts the final string to lowercase.
function cp_normalizeURL(rawUrl) {
    try {
        let url = rawUrl.trim();
        // Add protocol if missing so URL constructor works
        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
        const parsed = new URL(url);
        // hostname without www
        let host = parsed.hostname.replace(/^www\./i, '');
        // include pathname AND search params (to catch long payloads/sql injections)
        let path = (parsed.pathname + parsed.search).replace(/\/$/, '');
        return (host + path).toLowerCase();
    } catch {
        // Fallback
        return rawUrl
            .replace(/^(https?:\/\/)?(www\.)?/i, '')
            .toLowerCase()
            .replace(/\/$/, '');
    }
}

/**
 * Extracts just the hostname (no path) from a URL for TLD and IP checks.
 * @param {string} rawUrl
 * @returns {string}
 */
// Function: cp_getHostname
// - Inputs: rawUrl (string).
// - Step 1: Cleans and ensures a protocol prefix for the raw URL.
// - Step 2: Extracts and returns the hostname portion of the parsed URL in lowercase.
// - Step 3: Employs a split-fallback algorithm if standard URL parsing fails.
function cp_getHostname(rawUrl) {
    try {
        let url = rawUrl.trim();
        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
        return new URL(url).hostname.toLowerCase();
    } catch {
        return cp_normalizeURL(rawUrl).split('/')[0];
    }
}

/**
 * Computes Shannon entropy of a string.
 * Higher entropy means more character randomness (obfuscated domains score higher).
 * @param {string} str
 * @returns {number}
 */
// Function: cp_shannonEntropy
// - Inputs: str (string).
// - Step 1: Rejects empty inputs and calculates string length.
// - Step 2: Loops through character tokens to calculate frequency distribution.
// - Step 3: Computes Shannon entropy formula by summing log probability values.
// - Step 4: Returns numerical entropy value indicating random noise.
function cp_shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    return Object.values(freq).reduce((acc, count) => {
        const p = count / len;
        return acc - p * Math.log2(p);
    }, 0);
}

/**
 * Computes Levenshtein edit distance between two strings.
 * Uses space-optimised two-row DP.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
// Function: cp_levenshtein
// - Inputs: a (string), b (string).
// - Step 1: Returns 0 instantly if string structures are identical.
// - Step 2: Extracts only the base hostname portions for distance evaluation.
// - Step 3: Initializes two rows of tracking indices for Space-Optimized Dynamic Programming.
// - Step 4: Computes the Levenshtein distance by checking deletions, insertions, and substitutions.
// - Step 5: Returns the minimum number of character edits needed to transform string a into b.
function cp_levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    // Only compare the hostname portions for efficiency and accuracy
    const extractHost = s => s.split('/')[0];
    a = extractHost(a);
    b = extractHost(b);

    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    let curr = new Array(b.length + 1);
    for (let i = 1; i <= a.length; i++) {
        curr[0] = i;
        for (let j = 1; j <= b.length; j++) {
            curr[j] = a[i - 1] === b[j - 1]
                ? prev[j - 1]
                : 1 + Math.min(prev[j - 1], prev[j], curr[j - 1]);
        }
        [prev, curr] = [curr, prev];
    }
    return prev[b.length];
}

// ---------------------------------------------------------------------------
// FEATURE EXTRACTION
// ---------------------------------------------------------------------------

/**
 * Extracts all heuristic signals from a normalized URL.
 * @param {string} normalized — output of cp_normalizeURL()
 * @param {string} hostname   — output of cp_getHostname()
 * @param {string} rawUrl     — original URL
 * @returns {Object} feature map
 */
// Function: cp_extractFeatures
// - Inputs: normalized (string), hostname (string), rawUrl (string).
// - Step 1: Checks for insecure HTTP protocol usage.
// - Step 2: Computes subdomain nesting depth and extracts registered base domain.
// - Step 3: Splits hostname into sub-chunks to compare with brand target cores.
// - Step 4: Employs Levenshtein checks on raw and leet-speak normalized chunks to flag typosquatting.
// - Step 5: Executes regex patterns to detect raw IP addresses.
// - Step 6: Scans suffix tokens for suspicious, cheap, or abuse-prone TLDs.
// - Step 7: Verifies punycode tags (`xn--`) indicating homoglyph character spoofing.
// - Step 8: Checks for standard email or spoofing routing symbols (`@`).
// - Step 9: Flags excessive hyphens, numeric subdomains, and long subdomains.
// - Step 10: Checks for brand keyword impersonation, suspicious path keywords, redirects, and segment depth.
// - Step 11: Compiles all values into a cohesive feature analytics mapping.
function cp_extractFeatures(normalized, hostname, rawUrl = '') {
    const hasNoHttps = rawUrl && !/^https:\/\//i.test(rawUrl.trim());

    // Subdomain depth (number of dots in hostname - 1 for TLD)
    const hostParts = hostname.split('.');
    const subdomainDepth = Math.max(0, hostParts.length - 2);

    // Registered domain = last 2 parts (e.g. "wikiobits.com")
    const registeredDomain = hostParts.slice(-2).join('.');

    // Levenshtein against all targets — compare domain chunks to catch things like 'paypa1-secure.com'
    let minDistance = Infinity;
    let closestTarget = '';
    const rawHost = hostname.replace(/^www\./i, '');
    const hostChunks = rawHost.split(/[-.]/); // Split on dots AND hyphens
    const leetChunks = hostChunks.map(c => cp_normalizeLeet(c));
    
    for (const target of CP_TARGETS) {
        const targetCore = target.split('.')[0]; // e.g. paypal.com -> paypal
        
        for (let i = 0; i < hostChunks.length; i++) {
            const chunkRaw = hostChunks[i];
            const chunkLeet = leetChunks[i];
            
            // Compare each chunk to the target core
            const dRaw = cp_levenshtein(chunkRaw, targetCore);
            const dLeet = cp_levenshtein(chunkLeet, targetCore);
            const d = Math.min(dRaw, dLeet);
            
            // We only care if it's very close (1-3 distance) AND the chunk length is similar
            if (d < minDistance && Math.abs(chunkRaw.length - targetCore.length) <= 3) {
                // If it's an exact match on the core name (d=0), ensure the actual domain is NOT the legitimate target
                if (d === 0 && target.split('/')[0].replace(/^www\./i, '') === registeredDomain) {
                    continue; // This is the actual legitimate site, do not flag it.
                }
                // Ignore meaningless matches where more than 45% of the string is different
                if (d > 0 && d / Math.max(chunkRaw.length, targetCore.length) >= 0.45) {
                    continue;
                }
                minDistance = d;
                closestTarget = target;
            }
        }
    }

    // IP address detection (IPv4 in hostname)
    const hasIPAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    // Suspicious TLD check
    const hasSuspiciousTLD = CP_SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));

    // Punycode / IDN homoglyph detection
    const hasPunycode = hostname.includes('xn--');

    // @ sign in the full URL (before normalization)
    const hasAtSign = normalized.includes('@');

    // Excessive hyphens in hostname (> 2)
    const hyphenCount = (hostname.match(/-/g) || []).length;
    const hasExcessiveHyphens = hyphenCount > 2;

    // Numeric subdomain (e.g. 192-168.secure-bank.com)
    const hasNumericSubdomain = hostParts.slice(0, -2).some(part => /^\d+$/.test(part));

    // Long subdomain segment > 20 chars
    const hasLongSubdomain = hostParts.slice(0, -2).some(part => part.length > 20);

    // Shannon entropy of the hostname only
    const entropy = cp_shannonEntropy(hostname);

    // URL length (full normalized)
    const length = normalized.length;

    // --- v2.1 NEW SIGNALS ---

    // Domain name without TLD (e.g. "wikiobits")
    const domainNameOnly = hostParts[hostParts.length - 2] || '';

    // Numeric main domain (e.g. 192.com)
    const hasNumericMainDomain = /^\d+$/.test(domainNameOnly);

    // Brand keyword appears in domain name but this isn't the brand's own domain
    const hasBrandKeywordInHost = CP_BRAND_KEYWORDS.some(kw =>
        domainNameOnly.includes(kw) &&
        !CP_GLOBAL_WHITELIST.some(w => registeredDomain === w || registeredDomain.endsWith('.' + w)) &&
        !CP_TARGETS.some(t => t.split('/')[0].replace(/^www\./i, '') === registeredDomain)
    );

    // Suspicious keyword in the URL path
    const cleanHost = hostname.replace(/^www\./i, '');
    const pathPart = normalized.startsWith(cleanHost) ? normalized.slice(cleanHost.length) : '';
    const hasSuspiciousPathKeyword = CP_SUSPICIOUS_PATH_KEYWORDS.some(kw => pathPart.includes(kw));

    // Redirect pattern in path
    const hasRedirectPattern = CP_REDIRECT_PATTERNS.some(p => pathPart.includes(p));

    // Many path segments (> 5 slashes in path)
    const hasManyPathSegments = (pathPart.match(/\//g) || []).length > 5;

    // Safe path keywords
    const hasSafePathKeyword = CP_SAFE_PATH_KEYWORDS.some(kw => pathPart.includes(kw));

    return {
        length,
        subdomainDepth,
        entropy,
        minDistance,
        closestTarget,
        hasIPAddress,
        hasSuspiciousTLD,
        hasPunycode,
        hasAtSign,
        hasExcessiveHyphens,
        hasNumericSubdomain,
        hasLongSubdomain,
        // v2.1
        hasNumericMainDomain,
        hasBrandKeywordInHost,
        hasSuspiciousPathKeyword,
        hasRedirectPattern,
        hasManyPathSegments,
        hasSafePathKeyword,
        domainNameOnly,
        registeredDomain,
        pathPart,
        hasNoHttps
    };
}

// ---------------------------------------------------------------------------
// SCORING ENGINE
// ---------------------------------------------------------------------------

/**
 * Converts extracted features into a 0–99 probability score.
 * @param {Object} features — output of cp_extractFeatures()
 * @returns {{ score: number, components: Object }}
 */
// Function: cp_scoreFeatures
// - Inputs: features (object).
// - Step 1: Initializes an empty score component database.
// - Step 2: Applies weighted penalties for HTTP usage, long URLs, subdomains, and hostname entropy.
// - Step 3: Assigns gradient penalty weights based on computed typosquatting Levenshtein distance.
// - Step 4: Adds weights for binary flags (IP addresses, suspicious TLDs, punycode, etc.).
// - Step 5: Adds weights for new signals (brand impersonation, path keywords, redirect paths).
// - Step 6: Aggregates all active component weights together.
// - Step 7: Clamps the aggregated percentage score between 1% and 99%.
function cp_scoreFeaturesLegacy(features) {
    return cp_scoreFeatures(features);
}

function cp_clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
}

function cp_sigmoid(value) {
    return 1 / (1 + Math.exp(-value));
}

function cp_round(value, digits = 4) {
    const factor = Math.pow(10, digits);
    return Math.round(value * factor) / factor;
}

function cp_toBinary(value) {
    return value ? 1 : 0;
}

function cp_buildFeatureVector(features) {
    let levenshteinSimilarity = 0;
    if (features.minDistance === 0 || features.minDistance === 1) {
        levenshteinSimilarity = 1;
    } else if (features.minDistance === 2) {
        levenshteinSimilarity = 0.7;
    } else if (features.minDistance === 3) {
        levenshteinSimilarity = 0.4;
    }

    return {
        noHttps: cp_toBinary(features.hasNoHttps),
        length: cp_clamp((features.length - 30) / 120, 0, 1),
        subdomainDepth: cp_clamp((features.subdomainDepth - 1) / 4, 0, 1),
        entropy: cp_clamp((features.entropy - 3.5) / 1.5, 0, 1),
        levenshteinSimilarity,
        ipAddress: cp_toBinary(features.hasIPAddress),
        suspiciousTld: cp_toBinary(features.hasSuspiciousTLD),
        punycode: cp_toBinary(features.hasPunycode),
        atSign: cp_toBinary(features.hasAtSign),
        excessiveHyphens: cp_toBinary(features.hasExcessiveHyphens),
        numericSubdomain: cp_toBinary(features.hasNumericSubdomain),
        longSubdomain: cp_toBinary(features.hasLongSubdomain),
        numericMainDomain: cp_toBinary(features.hasNumericMainDomain),
        brandKeywordInHost: cp_toBinary(features.hasBrandKeywordInHost),
        suspiciousPathKeyword: cp_toBinary(features.hasSuspiciousPathKeyword),
        redirectPattern: cp_toBinary(features.hasRedirectPattern),
        manyPathSegments: cp_toBinary(features.hasManyPathSegments),
        safePathKeyword: cp_toBinary(features.hasSafePathKeyword),
    };
}

function cp_buildDecisionPath(rawUrl, targetUrl, features, modelTrace, probability) {
    const extractedUrl = targetUrl !== rawUrl ? targetUrl : 'No wrapped URL detected';
    const active = modelTrace.activeFeatures.length
        ? modelTrace.activeFeatures.join(', ')
        : 'none';
    const inferenceStep = features.hasNoHttps
        ? `Edge-AI inference: ${modelTrace.modelId} produced ${probability}% risk after enforcing the no-HTTPS high-risk rule`
        : `Edge-AI inference: ${modelTrace.modelId} produced ${probability}% risk against a ${modelTrace.threshold}% threshold`;

    return [
        `Click captured: ${rawUrl}`,
        `Wrapped URL extraction: ${extractedUrl}`,
        `Normalized host: ${features.registeredDomain || features.domainNameOnly || 'unknown'}`,
        `Feature vector activated: ${active}`,
        inferenceStep,
        `XAI synthesis: risk score and active signals were converted into the user-facing explanation`,
    ];
}

// v2.2 Edge-AI scoring override: local feature vector x weight matrix + sigmoid.
function cp_scoreFeatures(features) {
    const vector = cp_buildFeatureVector(features);
    const components = {};
    let linearScore = CP_EDGE_AI_MODEL.bias;

    for (const featureName of CP_EDGE_AI_MODEL.featureOrder) {
        const value = vector[featureName] || 0;
        const weight = CP_EDGE_AI_MODEL.weights[featureName] || 0;
        const contribution = value * weight;
        components[featureName] = cp_round(contribution);
        linearScore += contribution;
    }

    const sigmoidProbability = cp_sigmoid(linearScore) * 100;
    const probability = Math.min(99, Math.max(1, Math.round(sigmoidProbability)));
    const activeFeatures = CP_EDGE_AI_MODEL.featureOrder.filter(name => Math.abs(vector[name] || 0) > 0);

    return {
        probability,
        components,
        modelTrace: {
            modelId: CP_EDGE_AI_MODEL.id,
            modelType: CP_EDGE_AI_MODEL.type,
            threshold: CP_EDGE_AI_MODEL.threshold,
            bias: CP_EDGE_AI_MODEL.bias,
            featureVector: vector,
            linearScore: cp_round(linearScore),
            sigmoidProbability: cp_round(sigmoidProbability, 2),
            activeFeatures,
        },
    };
}

// ---------------------------------------------------------------------------
// NARRATIVE GENERATION (XAI)
// ---------------------------------------------------------------------------

/**
 * Generates a human-readable explanation for the risk score.
 * @param {number} probability
 * @param {Object} features
 * @returns {{ riskLevel: string, narrative: string, color: string }}
 */
// Function: cp_generateNarrative
// - Inputs: probability (number), features (object).
// - Step 1: Sets risk level category and display color based on the 35% score threshold.
// - Step 2: Gathers structured text explanations for all triggered high-confidence binary signals.
// - Step 3: Appends textual reasons for continuous characteristics (depth, entropy, length).
// - Step 4: Compiles all reasons into a cohesive, human-readable narrative explanation.
function cp_generateNarrative(probability, features) {
    let riskLevel, color;
    const reasons = [];

    if (probability >= CP_RISK_THRESHOLD) {
        riskLevel = 'HIGH RISK';
        color = '#c0392b';
    } else {
        riskLevel = 'SAFE';
        color = '#27ae60';
    }

    // Build reason list from triggered features

    // --- High-confidence binary signals ---
    if (features.hasIPAddress) {
        reasons.push('An IP address is used instead of a domain name — a classic phishing indicator.');
    }
    if (features.hasPunycode) {
        reasons.push('The domain uses Punycode (xn--) encoding, which can disguise lookalike characters (homoglyph attack).');
    }
    if (features.hasAtSign) {
        reasons.push('The URL contains an "@" symbol, which browsers use to redirect to a different host — a common phishing trick.');
    }
    if (features.hasSuspiciousTLD) {
        reasons.push('The domain uses a high-risk top-level domain (TLD) frequently associated with malicious sites.');
    }
    if (features.hasExcessiveHyphens) {
        reasons.push('The hostname contains an excessive number of hyphens, a common obfuscation pattern.');
    }
    if (features.hasNumericSubdomain) {
        reasons.push('A subdomain appears to be a numeric value, which is unusual for legitimate sites.');
    }
    if (features.hasLongSubdomain) {
        reasons.push('An unusually long subdomain segment was detected, sometimes used to bury the real domain visually.');
    }
    if (features.hasNumericMainDomain) {
        reasons.push(`The main domain name "${features.domainNameOnly}" is entirely numeric, which is rare for legitimate sites and common in malicious infrastructure.`);
    }
    if (features.hasBrandKeywordInHost) {
        reasons.push(`The domain closely resembles a known protected brand (impersonation), attempting to deceive the user.`);
    }
    if (features.minDistance <= 3 && features.minDistance > 0) {
        reasons.push(`The domain closely resembles a known protected brand (typosquatting), attempting to deceive the user.`);
    }
    if (features.hasSuspiciousPathKeyword) {
        reasons.push(`The URL path contains a keyword commonly found in credential-harvesting phishing pages.`);
    }
    if (features.hasRedirectPattern) {
        reasons.push('The URL path contains a redirect pattern, often used to funnel victims to attacker-controlled pages.');
    }
    if (features.hasNoHttps) {
        reasons.push('The connection is not secure, which is a high risk for data interception.');
    }
    if (features.hasSafePathKeyword) {
        reasons.push('The URL contains safe informational keywords (e.g. contact, report, learn more) which indicates a legitimate sub-page.');
    }

    // --- Continuous signals (these contribute to the score and must appear in the narrative) ---

    // Subdomain depth
    if (features.subdomainDepth >= 3) {
        reasons.push(`Unusually deep subdomain nesting (${features.subdomainDepth} levels) is used to obscure the real domain.`);
    } else if (features.subdomainDepth === 2) {
        reasons.push(`Multiple subdomain layers (${features.subdomainDepth} levels) were detected, which can be used to mislead users about the true registered domain.`);
    }

    // Shannon entropy
    if (features.entropy > 4.0) {
        reasons.push(`High character entropy (${features.entropy.toFixed(2)}) in the hostname suggests a randomly generated or obfuscated domain.`);
    } else if (features.entropy > 3.5) {
        reasons.push(`Elevated character entropy (${features.entropy.toFixed(2)}) was detected in the hostname, indicating structural complexity that warrants caution.`);
    }

    // URL length
    if (features.length > 75) {
        reasons.push(`The URL is very long (${features.length} characters), a tactic used to bury the true destination or embed hidden tracking parameters.`);
    } else if (features.length > 50) {
        reasons.push(`The URL is longer than average (${features.length} characters), which may indicate an attempt to obscure its true destination.`);
    }

    // Path segment count
    const segmentCount = (features.pathPart.match(/\//g) || []).length;
    if (segmentCount > 4) {
        reasons.push(`The URL contains ${segmentCount} path segments, which can be used to disguise the true nature of the destination page.`);
    }

    let narrative;
    if (reasons.length === 0) {
        narrative = 'No significant risk signals were detected. The URL structure appears standard and consistent with legitimate sites.';
    } else {
        narrative = reasons.join(' ');
    }

    return { riskLevel, narrative, color };
}

// ---------------------------------------------------------------------------
// PUBLIC API
// ---------------------------------------------------------------------------

/**
 * Main entry point. Analyzes a URL and returns a complete result object.
 * This is the ONLY function that content.js and popup.js should call.
 *
 * @param {string} rawUrl — The raw URL string (from href or user input)
 * @returns {{
 *   probability: number,
 *   riskLevel: string,
 *   color: string,
 *   narrative: string,
 *   features: Object,
 *   components: Object,
 *   normalizedUrl: string,
 *   hostname: string,
 *   latency: number
 * }}
 */
// Function: cp_analyzeURL
// - Inputs: rawUrl (string).
// - Step 1: Starts performance timing tracking for analysis latency metrics.
// - Step 2: Extracts, normalizes, and fetches the hostname parts of the URL.
// - Step 3: Bypasses further calculations if the target domain exists on the global trusted whitelist.
// - Step 4: Extracts detailed features from the normalized URL.
// - Step 5: Scores the extracted features to determine threat level percentage.
// - Step 6: Generates a natural language explanation for why the URL is flagged.
// - Step 7: Computes elapsed latency time and returns a unified analysis result payload.
function cp_analyzeURL(rawUrl) {
    const t0 = performance.now();

    const targetUrl = cp_extractWrappedURL(rawUrl);
    const normalized = cp_normalizeURL(targetUrl);
    const hostname = cp_getHostname(targetUrl);
    const targetUsesHttps = /^https:\/\//i.test(String(targetUrl).trim());

    // --- Fast-path: globally whitelisted domains are always SAFE ---
    // This ensures the popup gives the same result as the speed-bump bypass.
    if (targetUsesHttps && cp_isWhitelisted(targetUrl)) {
        const latency = parseFloat((performance.now() - t0).toFixed(2));
        // Use a clean all-false features object so NO warning pills are shown
        const cleanFeatures = {
            length: normalized.length,
            subdomainDepth: 0,
            entropy: cp_shannonEntropy(cp_getHostname(targetUrl)),
            minDistance: Infinity,
            closestTarget: '',
            hasIPAddress: false,
            hasSuspiciousTLD: false,
            hasPunycode: false,
            hasAtSign: false,
            hasExcessiveHyphens: false,
            hasNumericSubdomain: false,
            hasLongSubdomain: false,
            hasNumericMainDomain: false,
            hasBrandKeywordInHost: false,
            hasSuspiciousPathKeyword: false,
            hasRedirectPattern: false,
            hasManyPathSegments: false,
            hasSafePathKeyword: false,
            hasNoHttps: false,
            domainNameOnly: '',
            registeredDomain: '',
            pathPart: '',
        };
        const modelTrace = {
            modelId: CP_EDGE_AI_MODEL.id,
            modelType: 'deterministic global whitelist bypass',
            threshold: CP_EDGE_AI_MODEL.threshold,
            bias: 0,
            featureVector: {},
            linearScore: 0,
            sigmoidProbability: 1,
            activeFeatures: ['globalWhitelist'],
        };
        return {
            probability: 1,
            riskLevel: 'SAFE',
            color: '#27ae60',
            narrative: `This URL belongs to a globally trusted domain (${hostname.replace(/^www\./, '')}). It is on ConnectProtect\'s global whitelist and has been verified as a well-known, legitimate site.`,
            features: cleanFeatures,
            components: {},
            modelTrace,
            decisionPath: [
                `Click captured: ${rawUrl}`,
                `Host normalized: ${hostname.replace(/^www\./, '')}`,
                'Deterministic filter: matched global whitelist',
                'Edge-AI inference: bypassed because the domain is pre-trusted',
                'XAI synthesis: safe whitelist explanation generated',
            ],
            xaiMode: 'Local generative XAI synthesis',
            normalizedUrl: normalized,
            hostname,
            latency,
        };
    }

    const features = cp_extractFeatures(normalized, hostname, targetUrl);
    const { probability, components, modelTrace } = cp_scoreFeatures(features);

    // Guard: clamp probability to a valid number in case of any NaN propagation
    let safeProbability = Number.isFinite(probability) ? Math.min(99, Math.max(1, probability)) : 1;
    if (features.hasNoHttps) {
        safeProbability = Math.max(safeProbability, CP_NO_HTTPS_RISK_FLOOR);
        modelTrace.activeFeatures = Array.from(new Set([...modelTrace.activeFeatures, 'noHttps']));
        modelTrace.noHttpsEnforced = true;
        modelTrace.noHttpsRiskFloor = CP_NO_HTTPS_RISK_FLOOR;
    }

    const { riskLevel, narrative, color } = cp_generateNarrative(safeProbability, features);
    const latency = parseFloat((performance.now() - t0).toFixed(2));
    const decisionPath = cp_buildDecisionPath(rawUrl, targetUrl, features, modelTrace, safeProbability);

    return {
        probability: safeProbability,
        riskLevel,
        color,
        narrative,
        features,
        components,
        modelTrace,
        decisionPath,
        xaiMode: 'Local generative XAI synthesis',
        normalizedUrl: normalized,
        hostname,
        latency,
    };
}

/**
 * Checks if a URL's hostname matches the global whitelist.
 * @param {string} rawUrl
 * @returns {boolean}
 */
// Function: cp_isWhitelisted
// - Inputs: rawUrl (string).
// - Step 1: Extracts any wrapped URL parameters from the query line.
// - Step 2: Standardizes the hostname by removing any "www." prefix.
// - Step 3: Compares the cleaned hostname against the global whitelist of trusted domains.
function cp_isWhitelisted(rawUrl) {
    const targetUrl = cp_extractWrappedURL(rawUrl);
    const hostname = cp_getHostname(targetUrl).toLowerCase();
    // Strip only the www. prefix – other subdomains are treated as distinct hosts
    const cleanHost = hostname.startsWith('www.') ? hostname.slice(4) : hostname;
    // Direct match against the global whitelist (which contains base domains)
    return CP_GLOBAL_WHITELIST.some(domain => cleanHost === domain);
}
