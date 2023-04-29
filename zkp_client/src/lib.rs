pub enum ZkpClientRegistrationStatus {
    AlreadyRegistered,
    Registered,
}

pub enum ZkpClientAuthenticationStatus {
    Authenticated,
    NotAuthenticated,
    UnregisteredUser,
}

pub mod zkp_auth_client;
