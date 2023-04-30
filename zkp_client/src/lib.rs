/// The possible states for the user registration step
pub enum ZkpClientRegistrationStatus {
    AlreadyRegistered,
    Registered,
}

/// The possible states for the authentication step
pub enum ZkpClientAuthenticationStatus {
    Authenticated { session_id: String },
    NotAuthenticated { status: String },
    UnregisteredUser,
}

pub mod zkp_auth_client;
