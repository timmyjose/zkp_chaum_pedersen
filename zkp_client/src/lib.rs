pub enum ZkpClientRegistrationStatus {
    AlreadyRegistered,
    Registered,
}

pub enum ZkpClientAuthenticationStatus {
    Authenticated { session_id: String },
    NotAuthenticated { status: String },
    UnregisteredUser,
}

pub mod zkp_auth_client;
