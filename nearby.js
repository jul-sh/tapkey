'use strict';

const elements = {
  title: document.getElementById('title'),
  summary: document.getElementById('summary'),
  details: document.getElementById('details'),
  panelNote: document.getElementById('panel-note'),
  steps: document.getElementById('steps'),
  callout: document.getElementById('callout'),
  start: document.getElementById('start'),
  status: document.getElementById('status'),
  bridgeHint: document.getElementById('bridge-hint')
};

const bridge = (() => {
  const handler = window.webkit?.messageHandlers?.tapkey;
  if (handler && typeof handler.postMessage === 'function') {
    return { kind: 'native', handler };
  }
  return { kind: 'missing' };
})();

let runState = { kind: 'loading' };

const textDecoder = new TextDecoder();

function updateStatus(message) {
  elements.status.textContent = message;
}

function setButton(label, disabled) {
  elements.start.textContent = label;
  elements.start.disabled = disabled;
}

function decodeBase64URL(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function encodeBase64URL(value) {
  const bytes = value instanceof Uint8Array
    ? value
    : value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);

  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function readConfigToken() {
  const hash = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
  const hashParams = new URLSearchParams(hash);
  if (hashParams.has('cfg')) {
    return hashParams.get('cfg');
  }

  const queryParams = new URLSearchParams(location.search);
  return queryParams.get('cfg');
}

function readRequiredString(source, key) {
  if (typeof source[key] !== 'string' || source[key].length === 0) {
    throw new Error(`Missing ${key} in nearby flow config.`);
  }
  return source[key];
}

function readOptionalString(source, key) {
  if (!(key in source) || source[key] === null || source[key] === undefined) {
    return null;
  }
  if (typeof source[key] !== 'string' || source[key].length === 0) {
    throw new Error(`Invalid ${key} in nearby flow config.`);
  }
  return source[key];
}

function parseSession() {
  const token = readConfigToken();
  if (!token) {
    return { kind: 'missing-config' };
  }

  try {
    const raw = JSON.parse(textDecoder.decode(decodeBase64URL(token)));
    const operation = readRequiredString(raw, 'operation');
    const common = {
      rpId: readRequiredString(raw, 'rpId'),
      challengeBase64URL: readRequiredString(raw, 'challengeBase64URL'),
      prfSaltBase64URL: readRequiredString(raw, 'prfSaltBase64URL')
    };

    switch (operation) {
      case 'register':
        return {
          kind: 'configured',
          flow: {
            kind: 'register',
            ...common,
            userIDBase64URL: readRequiredString(raw, 'userIDBase64URL'),
            userName: readRequiredString(raw, 'userName')
          }
        };
      case 'assert':
        return {
          kind: 'configured',
          flow: {
            kind: 'assert',
            ...common,
            keyName: readRequiredString(raw, 'keyName'),
            preferredCredentialIDBase64URL: readOptionalString(raw, 'preferredCredentialIDBase64URL')
          }
        };
      default:
        return { kind: 'invalid-config', message: `Unsupported nearby flow operation: ${operation}` };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { kind: 'invalid-config', message };
  }
}

function postToTapkey(payload) {
  if (bridge.kind === 'native') {
    bridge.handler.postMessage(JSON.stringify(payload));
    return;
  }

  elements.bridgeHint.hidden = false;
  console.log('tapkey nearby payload', payload);
}

function describeError(error, flowKind) {
  const code = error && typeof error === 'object' && 'name' in error ? error.name : null;
  const fallback = error instanceof Error ? error.message : String(error);

  switch (code) {
    case 'AbortError':
      return { code, message: 'The passkey request was interrupted before it finished.' };
    case 'ConstraintError':
      return { code, message: 'This passkey provider cannot satisfy tapkey\'s passkey requirements.' };
    case 'InvalidStateError':
      return flowKind === 'register'
        ? { code, message: 'A tapkey passkey may already exist on this authenticator.' }
        : { code, message: 'The selected passkey could not be used for this request.' };
    case 'NotAllowedError':
      return flowKind === 'register'
        ? { code, message: 'Passkey creation was cancelled or timed out.' }
        : { code, message: 'Passkey approval was cancelled or timed out.' };
    case 'NotSupportedError':
      return { code, message: fallback || 'This nearby passkey flow does not support WebAuthn PRF.' };
    case 'SecurityError':
      return { code, message: 'This page is not allowed to use passkeys for tapkey.jul.sh.' };
    default:
      return { code, message: fallback };
  }
}

function showFailure(failure, flowKind) {
  runState = { kind: 'ready', flowKind };
  updateStatus(failure.message);
  setButton(flowKind === 'register' ? 'Try again' : 'Try again', false);
  postToTapkey({ type: 'error', code: failure.code, message: failure.message });
}

function showSuccess(payload) {
  runState = { kind: 'finished' };
  updateStatus('Handing the result back to tapkey…');
  postToTapkey(payload);
}

function createRegisterRequest(flow) {
  return {
    publicKey: {
      challenge: decodeBase64URL(flow.challengeBase64URL),
      rp: {
        id: flow.rpId,
        name: 'tapkey'
      },
      user: {
        id: decodeBase64URL(flow.userIDBase64URL),
        name: flow.userName,
        displayName: flow.userName
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required'
      },
      attestation: 'none',
      timeout: 120000,
      extensions: {
        prf: {
          eval: { first: decodeBase64URL(flow.prfSaltBase64URL) }
        }
      }
    }
  };
}

function createAssertRequest(flow) {
  const request = {
    publicKey: {
      challenge: decodeBase64URL(flow.challengeBase64URL),
      rpId: flow.rpId,
      userVerification: 'required',
      timeout: 120000,
      extensions: {
        prf: {
          eval: { first: decodeBase64URL(flow.prfSaltBase64URL) }
        }
      }
    }
  };

  if (flow.preferredCredentialIDBase64URL) {
    request.publicKey.allowCredentials = [
      {
        type: 'public-key',
        id: decodeBase64URL(flow.preferredCredentialIDBase64URL)
      }
    ];
  }

  return request;
}

async function runRegister(flow) {
  updateStatus('Waiting for passkey creation…');
  const credential = await navigator.credentials.create(createRegisterRequest(flow));
  if (!credential) {
    throw new Error('Passkey creation returned no credential.');
  }

  const extensionResults = credential.getClientExtensionResults?.() || {};
  const prfSupported = extensionResults.prf?.enabled === true;
  if (!prfSupported) {
    throw Object.assign(
      new Error('The passkey was created, but this authenticator does not support WebAuthn PRF.'),
      { name: 'NotSupportedError' }
    );
  }

  showSuccess({
    type: 'register-success',
    credentialId: encodeBase64URL(credential.rawId)
  });
}

async function runAssertion(flow) {
  updateStatus('Waiting for passkey approval…');
  const credential = await navigator.credentials.get(createAssertRequest(flow));
  if (!credential) {
    throw new Error('Passkey approval returned no credential.');
  }

  const extensionResults = credential.getClientExtensionResults?.() || {};
  const prfFirst = extensionResults.prf?.results?.first;
  if (!prfFirst) {
    throw Object.assign(
      new Error('PRF output was not returned by this passkey flow.'),
      { name: 'NotSupportedError' }
    );
  }

  showSuccess({
    type: 'assert-success',
    credentialId: encodeBase64URL(credential.rawId),
    prfFirst: encodeBase64URL(prfFirst)
  });
}

function configureFlow(flow) {
  elements.bridgeHint.hidden = bridge.kind === 'native';

  if (!window.PublicKeyCredential || !navigator.credentials) {
    runState = { kind: 'blocked' };
    elements.summary.textContent = 'This web view cannot run WebAuthn.';
    elements.details.textContent = 'Nearby-device passkey flow requires WebAuthn support in WebKit.';
    elements.callout.textContent = 'Open this page from a current macOS build of tapkey.';
    setButton('Unavailable', true);
    updateStatus('WebAuthn is not available.');
    return;
  }

  switch (flow.kind) {
    case 'register':
      elements.title.textContent = 'Create the tapkey passkey';
      elements.summary.textContent = 'Create the passkey once, then tapkey can recover the same keys anywhere that passkey is available.';
      elements.details.textContent = 'If you do not want the passkey stored on this Mac, pick your iPhone or another nearby device in the passkey sheet.';
      elements.panelNote.textContent = 'The passkey becomes the root for every key tapkey derives later.';
      elements.steps.innerHTML = [
        '<li>Tap continue.</li>',
        '<li>Choose where the passkey should live.</li>',
        '<li>Approve the passkey creation.</li>'
      ].join('');
      elements.callout.textContent = 'If the only copy should stay on your iPhone, choose the nearby-device option when the passkey sheet appears.';
      setButton('Continue to register', false);
      updateStatus('Ready.');
      runState = { kind: 'ready', flowKind: 'register' };
      elements.start.addEventListener('click', async () => {
        if (runState.kind !== 'ready' || runState.flowKind !== 'register') {
          return;
        }

        runState = { kind: 'running', flowKind: 'register' };
        setButton('Registering…', true);

        try {
          await runRegister(flow);
        } catch (error) {
          showFailure(describeError(error, 'register'), 'register');
        }
      }, { once: false });
      return;
    case 'assert':
      elements.title.textContent = 'Use your tapkey passkey';
      elements.summary.textContent = 'Recover the key you asked for on this Mac. If the passkey is elsewhere, scan the QR code with your iPhone and approve there.';
      elements.details.textContent = `Requested key name: ${flow.keyName}`;
      elements.panelNote.textContent = 'Same passkey, same name, same derived key.';
      elements.steps.innerHTML = [
        '<li>Tap continue.</li>',
        '<li>Approve on this Mac or choose a nearby device.</li>',
        '<li>tapkey receives the PRF result and derives the key locally.</li>'
      ].join('');
      elements.callout.textContent = 'Only the requested secret is handed back to tapkey. The passkey itself stays with the authenticator that approved the request.';
      setButton('Continue to authenticate', false);
      updateStatus('Ready.');
      runState = { kind: 'ready', flowKind: 'assert' };
      elements.start.addEventListener('click', async () => {
        if (runState.kind !== 'ready' || runState.flowKind !== 'assert') {
          return;
        }

        runState = { kind: 'running', flowKind: 'assert' };
        setButton('Waiting…', true);

        try {
          await runAssertion(flow);
        } catch (error) {
          showFailure(describeError(error, 'assert'), 'assert');
        }
      }, { once: false });
      return;
    default:
      break;
  }
}

function showMissingConfig() {
  elements.title.textContent = 'Open this from tapkey';
  elements.summary.textContent = 'This page is the hosted WebAuthn step for tapkey.';
  elements.details.textContent = 'It expects a short-lived session config from the app, then performs either passkey registration or passkey approval.';
  elements.panelNote.textContent = 'Nothing useful happens here without that session config.';
  elements.callout.textContent = 'Use tapkey register or tapkey derive. The app opens this page when it needs nearby-device passkey flow.';
  setButton('Waiting for tapkey', true);
  updateStatus('No session config was provided.');
}

function showInvalidConfig(message) {
  elements.title.textContent = 'Nearby flow configuration error';
  elements.summary.textContent = 'The tapkey app opened this page with an invalid session config.';
  elements.details.textContent = 'Update tapkey and try again.';
  elements.panelNote.textContent = 'The hosted page and the app need to agree on the same message format.';
  elements.callout.textContent = message;
  setButton('Unavailable', true);
  updateStatus(message);
  postToTapkey({ type: 'error', code: 'InvalidConfig', message });
}

function main() {
  const session = parseSession();
  switch (session.kind) {
    case 'missing-config':
      showMissingConfig();
      return;
    case 'invalid-config':
      showInvalidConfig(session.message);
      return;
    case 'configured':
      configureFlow(session.flow);
      return;
    default:
      showInvalidConfig('Unknown nearby flow session state.');
  }
}

main();
