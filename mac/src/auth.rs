use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2::{define_class, msg_send, AnyThread, MainThreadOnly};
use objc2_authentication_services::{
    ASAuthorization, ASAuthorizationController, ASAuthorizationControllerDelegate,
    ASAuthorizationPlatformPublicKeyCredentialAssertion,
    ASAuthorizationPlatformPublicKeyCredentialDescriptor,
    ASAuthorizationPlatformPublicKeyCredentialProvider,
    ASAuthorizationPlatformPublicKeyCredentialRegistration,
};
use objc2_app_kit::NSWindow;
use objc2_foundation::{
    MainThreadMarker, NSArray, NSData, NSError, NSObject, NSObjectProtocol, NSString,
};
use std::cell::RefCell;

type RegistrationCb = Box<dyn Fn(RegistrationOutcome)>;
type AssertionCb = Box<dyn Fn(AssertionOutcome)>;

pub enum RegistrationOutcome {
    Success { credential_id: Vec<u8> },
    Error(String),
}

pub enum AssertionOutcome {
    Success {
        credential_id: Vec<u8>,
        prf_output: Vec<u8>,
    },
    Error(String),
}

// -- Registration Delegate --

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "TKRegistrationDelegate"]
    struct RegistrationDelegate;

    unsafe impl NSObjectProtocol for RegistrationDelegate {}

    unsafe impl ASAuthorizationControllerDelegate for RegistrationDelegate {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        unsafe fn did_complete(
            &self,
            _controller: &ASAuthorizationController,
            authorization: &ASAuthorization,
        ) {
            let credential: *const ASAuthorizationPlatformPublicKeyCredentialRegistration =
                msg_send![authorization, credential];
            if credential.is_null() {
                self.call(RegistrationOutcome::Error("unexpected credential type".into()));
                return;
            }

            let prf: *const NSObject = msg_send![credential, prf];
            if prf.is_null() {
                self.call(RegistrationOutcome::Error(
                    "passkey created but PRF is not supported by this authenticator".into(),
                ));
                return;
            }
            let is_supported: bool = msg_send![prf, isSupported];
            if !is_supported {
                self.call(RegistrationOutcome::Error(
                    "passkey created but PRF is not supported by this authenticator".into(),
                ));
                return;
            }

            let cred_id: *const NSData = msg_send![credential, credentialID];
            let bytes = nsdata_to_vec(&*cred_id);
            self.call(RegistrationOutcome::Success {
                credential_id: bytes,
            });
        }

        #[unsafe(method(authorizationController:didCompleteWithError:))]
        unsafe fn did_fail(&self, _controller: &ASAuthorizationController, error: &NSError) {
            match error.code() {
                1001 => self.call(RegistrationOutcome::Error("Registration cancelled.".into())),
                1004 => self.call(RegistrationOutcome::Error(
                    "registration failed — ensure your passkey provider is available".into(),
                )),
                _ => {
                    let desc = error.localizedDescription().to_string();
                    self.call(RegistrationOutcome::Error(format!(
                        "registration failed: {desc}"
                    )));
                }
            }
        }
    }
);

impl RegistrationDelegate {
    thread_local! {
        static CALLBACK: RefCell<Option<RegistrationCb>> = const { RefCell::new(None) };
    }

    pub fn new(mtm: MainThreadMarker, callback: RegistrationCb) -> Retained<Self> {
        Self::CALLBACK.with(|c| *c.borrow_mut() = Some(callback));
        unsafe { msg_send![Self::alloc(mtm), init] }
    }

    fn call(&self, outcome: RegistrationOutcome) {
        Self::CALLBACK.with(|c| {
            if let Some(cb) = c.borrow().as_ref() {
                cb(outcome);
            }
        });
    }
}

// -- Assertion Delegate --

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "TKAssertionDelegate"]
    struct AssertionDelegate;

    unsafe impl NSObjectProtocol for AssertionDelegate {}

    unsafe impl ASAuthorizationControllerDelegate for AssertionDelegate {
        #[unsafe(method(authorizationController:didCompleteWithAuthorization:))]
        unsafe fn did_complete(
            &self,
            _controller: &ASAuthorizationController,
            authorization: &ASAuthorization,
        ) {
            let credential: *const ASAuthorizationPlatformPublicKeyCredentialAssertion =
                msg_send![authorization, credential];
            if credential.is_null() {
                self.call(AssertionOutcome::Error("unexpected credential type".into()));
                return;
            }

            let prf: *const NSObject = msg_send![credential, prf];
            if prf.is_null() {
                self.call(AssertionOutcome::Error(
                    "PRF output not available. Your passkey may not support the PRF extension."
                        .into(),
                ));
                return;
            }
            let prf_first: *const NSData = msg_send![prf, first];
            if prf_first.is_null() {
                self.call(AssertionOutcome::Error("PRF first output is null".into()));
                return;
            }
            let prf_bytes = nsdata_to_vec(&*prf_first);

            let cred_id: *const NSData = msg_send![credential, credentialID];
            let cred_bytes = nsdata_to_vec(&*cred_id);

            self.call(AssertionOutcome::Success {
                credential_id: cred_bytes,
                prf_output: prf_bytes,
            });
        }

        #[unsafe(method(authorizationController:didCompleteWithError:))]
        unsafe fn did_fail(&self, _controller: &ASAuthorizationController, error: &NSError) {
            match error.code() {
                1001 => self.call(AssertionOutcome::Error("Authentication cancelled.".into())),
                1004 => self.call(AssertionOutcome::Error(
                    "authentication failed — biometric or passkey authentication may have failed"
                        .into(),
                )),
                _ => {
                    let desc = error.localizedDescription().to_string();
                    self.call(AssertionOutcome::Error(format!(
                        "authentication failed: {desc}"
                    )));
                }
            }
        }
    }
);

impl AssertionDelegate {
    thread_local! {
        static CALLBACK: RefCell<Option<AssertionCb>> = const { RefCell::new(None) };
    }

    pub fn new(mtm: MainThreadMarker, callback: AssertionCb) -> Retained<Self> {
        Self::CALLBACK.with(|c| *c.borrow_mut() = Some(callback));
        unsafe { msg_send![Self::alloc(mtm), init] }
    }

    fn call(&self, outcome: AssertionOutcome) {
        Self::CALLBACK.with(|c| {
            if let Some(cb) = c.borrow().as_ref() {
                cb(outcome);
            }
        });
    }
}

// -- Public helpers --

unsafe fn nsdata_to_vec(data: &NSData) -> Vec<u8> {
    let len: usize = msg_send![data, length];
    if len == 0 {
        return Vec::new();
    }
    let ptr: *const u8 = msg_send![data, bytes];
    std::slice::from_raw_parts(ptr, len).to_vec()
}

fn random_challenge() -> Vec<u8> {
    use rand::Rng;
    let mut buf = vec![0u8; 32];
    rand::thread_rng().fill(&mut buf[..]);
    buf
}

pub fn start_registration(
    mtm: MainThreadMarker,
    anchor: &NSWindow,
    callback: RegistrationCb,
) {
    unsafe {
        let rp = NSString::from_str("tapkey.jul.sh");
        let provider: Retained<ASAuthorizationPlatformPublicKeyCredentialProvider> = msg_send![
            ASAuthorizationPlatformPublicKeyCredentialProvider::alloc(),
            initWithRelyingPartyIdentifier: &*rp
        ];

        let challenge = NSData::with_bytes(&random_challenge());
        let name = NSString::from_str("tapkey");
        let user_id = NSData::with_bytes(b"tapkey-user");

        let request: Retained<NSObject> = msg_send![
            &provider,
            createCredentialRegistrationRequestWithChallenge: &*challenge,
            name: &*name,
            userID: &*user_id
        ];

        // Set PRF to check for support
        let check: Retained<NSObject> = msg_send![
            objc2::class!(ASAuthorizationPublicKeyCredentialPRFRegistrationInput),
            checkForSupport
        ];
        let _: () = msg_send![&request, setPrf: &*check];

        let requests = NSArray::from_retained_slice(&[request]);
        let controller: Retained<ASAuthorizationController> = msg_send![
            ASAuthorizationController::alloc(),
            initWithAuthorizationRequests: &*requests
        ];

        let delegate = RegistrationDelegate::new(mtm, callback);
        controller.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        // Set presentation context provider (NSWindow conforms in AppKit)
        let _: () = msg_send![&controller, setPresentationContextProvider: anchor];
        controller.performRequests();

        std::mem::forget(controller);
        std::mem::forget(delegate);
    }
}

pub fn start_assertion(
    mtm: MainThreadMarker,
    anchor: &NSWindow,
    key_name: &str,
    preferred_credential_id: Option<&[u8]>,
    callback: AssertionCb,
) {
    unsafe {
        let rp = NSString::from_str("tapkey.jul.sh");
        let provider: Retained<ASAuthorizationPlatformPublicKeyCredentialProvider> = msg_send![
            ASAuthorizationPlatformPublicKeyCredentialProvider::alloc(),
            initWithRelyingPartyIdentifier: &*rp
        ];

        let challenge = NSData::with_bytes(&random_challenge());
        let request: Retained<NSObject> = msg_send![
            &provider,
            createCredentialAssertionRequestWithChallenge: &*challenge
        ];

        // Set allowed credentials if we have a preferred one
        if let Some(cred_id) = preferred_credential_id {
            let cred_id_data = NSData::with_bytes(cred_id);
            let descriptor: Retained<ASAuthorizationPlatformPublicKeyCredentialDescriptor> =
                msg_send![
                    ASAuthorizationPlatformPublicKeyCredentialDescriptor::alloc(),
                    initWithCredentialID: &*cred_id_data
                ];
            let descriptors = NSArray::from_retained_slice(&[Retained::into_super(descriptor)]);
            let _: () = msg_send![&request, setAllowedCredentials: &*descriptors];
        }

        // Set PRF input
        let prf_salt = tapkey_core::prf_salt_for_name(key_name).expect("invalid key name");
        let salt_data = NSData::with_bytes(&prf_salt);

        let cls_values = objc2::class!(ASAuthorizationPublicKeyCredentialPRFAssertionInputValues);
        let input_values: *mut NSObject = msg_send![cls_values, alloc];
        let input_values: *mut NSObject = msg_send![
            input_values,
            initWithSaltInput1: &*salt_data,
            saltInput2: std::ptr::null::<NSData>()
        ];
        let input_values = Retained::retain(input_values).unwrap();

        let cls_input = objc2::class!(ASAuthorizationPublicKeyCredentialPRFAssertionInput);
        let prf_input: *mut NSObject = msg_send![cls_input, alloc];
        let prf_input: *mut NSObject = msg_send![
            prf_input,
            initWithInputValues: &*input_values,
            perCredentialInputValues: std::ptr::null::<NSObject>()
        ];
        let prf_input = Retained::retain(prf_input).unwrap();

        let _: () = msg_send![&request, setPrf: &*prf_input];

        let requests = NSArray::from_retained_slice(&[request]);
        let controller: Retained<ASAuthorizationController> = msg_send![
            ASAuthorizationController::alloc(),
            initWithAuthorizationRequests: &*requests
        ];

        let delegate = AssertionDelegate::new(mtm, callback);
        controller.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        let _: () = msg_send![&controller, setPresentationContextProvider: anchor];
        controller.performRequests();

        std::mem::forget(controller);
        std::mem::forget(delegate);
    }
}
