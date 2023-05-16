use std::str::FromStr;
use std::time::SystemTimeError;

use crate::database::connect;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use entity::{tokens as Tokens, users as Users};

use rand_core::OsRng;
use sea_orm::error::DbErr;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use totp_rs::{Algorithm, Secret, TotpUrlError, TOTP};
use uuid::Uuid;

#[derive(Debug, PartialEq, PartialOrd)]
pub struct UsernameAndPassword {
    pub username: String,
    pub password: String,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct TwoFactorLoginRequest {
    pub username: String,
    pub session_login_attempt_id: Uuid,
    pub otp: String,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub enum UserVerificationMethod {
    Watchword(UsernameAndPassword),
    TwoFactor(TwoFactorLoginRequest),
}

#[derive(Debug, PartialEq)]
pub enum UserCreationError {
    UserAlreadyExists,
    InvalidPassword(InvalidPassword),
    DatabaseError(DbErr),
    HashingFailure(argon2::password_hash::Error),
    UserIdParseFailure(uuid::Error),
}

#[derive(Debug, PartialEq, PartialOrd)]
pub enum InvalidPassword {
    PasswordTooShort,
    PasswordTooSimple,
    PasswordTooLong,
}

#[derive(Debug, PartialEq)]
enum UserGetError {
    UserDoesntExist,
    DatabaseError(DbErr),
    UserIdParseFailure(uuid::Error),
}

#[derive(Debug, PartialEq)]
enum UserVerificationError {
    UserDoesntExist,
    DatabaseError(DbErr),
    HashingFailure(argon2::password_hash::Error),
    UserIdParseFailure(uuid::Error),
}

#[derive(Debug, PartialEq)]
pub enum UserLoginError {
    UserDoesntExist,
    DatabaseError(DbErr),
    HashingFailure(argon2::password_hash::Error),
    VerificationFailed,
    UserIdParseFailure(uuid::Error),
    TokenParseFailure(uuid::Error),
    NoSuchTwoFactorSessionToken,
    TwoFactorNeeded(Uuid),
    IncorrectTwoFactor,
    AccountLocked, // reserved
}

#[derive(Debug, PartialEq)]
enum AuthTokenCreateType {
    TwoFactor,
    New,
    ReAuthenticate(Uuid),
}

#[derive(Debug, PartialEq)]
enum AuthTokenCreationFailure {
    DatabaseError(DbErr),
    TokenParseFailure(uuid::Error),
    NoSuchTwoFactorToken,
}

#[derive(Debug, PartialEq)]
pub enum TwoFactorInitErr {
    AlreadyEnabled,
    QrCreationFailure(String),
}

#[derive(Debug)]
pub enum TwoFactorVerifyToEnableFailure {
    TwoFactorAlreadyEnabled,
    TwoFactorNotCreated,
    ValidationTimedOut,
    TotpErr(TotpUrlError),
    SystemTimeError(SystemTimeError),
    TwoFactorIncorrect,
}

#[derive(Debug)]
enum TwoFactorVerifyErr {
    TwoFactorNotEnabled,
    SystemTimeError(SystemTimeError),
    TotpErr(TotpUrlError),
}

#[derive(Debug)]
pub enum VerifySessionTokenError {
    ExpiredToken,
    NoSuchToken,
    DatabaseError(DbErr),
}

async fn get_user(username: &str) -> Result<Users::Model, UserGetError> {
    let conn = connect().await;
    match conn {
        Ok(conn) => {
            let user = Users::Entity::find()
                .filter(Users::Column::Username.eq(username))
                .one(&conn)
                .await;
            match user {
                Ok(user) => match user {
                    None => {
                        return Err(UserGetError::UserDoesntExist);
                    }
                    Some(user) => Ok(user),
                },
                Err(err) => Err(UserGetError::DatabaseError(err)),
            }
        }
        Err(err) => Err(UserGetError::DatabaseError(sea_orm::DbErr::ConvertFromU64(
            err,
        ))),
    }
}

fn salt_and_hash_to_string(input: &String) -> Result<String, argon2::password_hash::Error> {
    Ok(Argon2::default()
        .hash_password(input.as_bytes(), &SaltString::generate(&mut OsRng))?
        .to_string())
}

pub async fn create_user(
    user_creation_request: &UsernameAndPassword,
) -> Result<Uuid, UserCreationError> {
    // Check if user exists already
    let user = get_user(&user_creation_request.username).await;
    match user {
        Err(UserGetError::UserDoesntExist) => (),
        Err(UserGetError::DatabaseError(err)) => return Err(UserCreationError::DatabaseError(err)),
        Err(UserGetError::UserIdParseFailure(err)) => {
            return Err(UserCreationError::UserIdParseFailure(err))
        }
        Ok(_) => return Err(UserCreationError::UserAlreadyExists),
    };
    // Check password strength
    // salt password and make a phc string
    let phc: String;
    let phc_res = salt_and_hash_to_string(&user_creation_request.password);
    match phc_res {
        Ok(phc_string) => phc = phc_string,
        Err(err) => return Err(UserCreationError::HashingFailure(err)),
    };

    // store salt in db
    let new_user = Users::ActiveModel {
        user_id: Set(Uuid::new_v4().to_string()),
        username: Set(user_creation_request.username.to_string()),
        phc_string: Set(Some(phc)),
        two_factor_enabled: Set(0),
        two_factor_secret: Set(None),
        two_factor_enable_date: Set(None),
    };

    let conn = connect().await;
    match conn {
        Ok(conn) => {
            let db_res = new_user.insert(&conn).await;
            match db_res {
                Ok(res) => match Uuid::parse_str(&res.user_id) {
                    Ok(user_id) => return Ok(user_id),
                    Err(err) => return Err(UserCreationError::UserIdParseFailure(err)),
                },
                Err(err) => return Err(UserCreationError::DatabaseError(err)),
            }
        }
        Err(err) => {
            return Err(UserCreationError::DatabaseError(
                sea_orm::DbErr::ConvertFromU64(err),
            ))
        }
    }
}

async fn verify_user(user_to_verify: &UsernameAndPassword) -> Result<bool, UserVerificationError> {
    // fetch user from db
    let user = get_user(&user_to_verify.username).await;
    match user {
        Ok(user) => match user.phc_string {
            None => return Ok(true), // No password users are always "verified". May add a toggle option to make this false.
            Some(phc) => {
                let hashing_res = PasswordHash::new(&phc);
                match hashing_res {
                    Ok(phc) => {
                        return Ok(Argon2::default()
                            .verify_password(&user_to_verify.password.as_bytes(), &phc)
                            .is_ok())
                    }
                    Err(err) => return Err(UserVerificationError::HashingFailure(err)),
                }
            }
        },
        Err(err) => match err {
            UserGetError::UserDoesntExist => return Err(UserVerificationError::UserDoesntExist),
            UserGetError::DatabaseError(err) => {
                return Err(UserVerificationError::DatabaseError(err))
            }
            UserGetError::UserIdParseFailure(err) => {
                return Err(UserVerificationError::UserIdParseFailure(err))
            }
        },
    }
}

// verify user AND return a login token
pub async fn login_user(user_to_verify: &UserVerificationMethod) -> Result<Uuid, UserLoginError> {
    match user_to_verify {
        UserVerificationMethod::Watchword(username_and_password) => {
            let verification_res = verify_user(&username_and_password).await;
            match verification_res {
                Ok(verified_password) => {
                    if !verified_password {
                        return Err(UserLoginError::VerificationFailed);
                    };

                    let user_res = get_user(&username_and_password.username).await;
                    let user: Users::Model;
                    match user_res {
                        Ok(user_data) => user = user_data,
                        Err(err) => match err {
                            UserGetError::UserDoesntExist => {
                                return Err(UserLoginError::UserDoesntExist)
                            }
                            UserGetError::DatabaseError(err) => {
                                return Err(UserLoginError::DatabaseError(err))
                            }
                            UserGetError::UserIdParseFailure(err) => {
                                return Err(UserLoginError::UserIdParseFailure(err))
                            }
                        },
                    }

                    // account is not locked here
                    // todo

                    // begin two factor auth flow if it is enabled - reject login and return 2fac token
                    if user.two_factor_enabled == 1 {
                        let two_factor_token = create_auth_token(
                            Uuid::parse_str(&user.user_id).unwrap(),
                            AuthTokenCreateType::TwoFactor,
                        )
                        .await;
                        match two_factor_token {
                            Ok(token) => return Err(UserLoginError::TwoFactorNeeded(token)),
                            Err(err) => match err {
                                AuthTokenCreationFailure::DatabaseError(err) => {
                                    return Err(UserLoginError::DatabaseError(err))
                                }
                                AuthTokenCreationFailure::TokenParseFailure(err) => {
                                    return Err(UserLoginError::TokenParseFailure(err))
                                }
                                AuthTokenCreationFailure::NoSuchTwoFactorToken => {
                                    return Err(UserLoginError::UserDoesntExist)
                                }
                            },
                        }
                    }

                    // Return auth token
                    let res = create_auth_token(
                        Uuid::parse_str(&user.user_id).unwrap(),
                        AuthTokenCreateType::New,
                    )
                    .await;
                    match res {
                        Ok(token) => return Ok(token),
                        Err(err) => match err {
                            AuthTokenCreationFailure::DatabaseError(err) => {
                                return Err(UserLoginError::DatabaseError(err))
                            }
                            AuthTokenCreationFailure::TokenParseFailure(err) => {
                                return Err(UserLoginError::TokenParseFailure(err))
                            }
                            AuthTokenCreationFailure::NoSuchTwoFactorToken => {
                                return Err(UserLoginError::UserDoesntExist)
                            }
                        },
                    }
                }
                Err(err) => match err {
                    UserVerificationError::UserDoesntExist => {
                        return Err(UserLoginError::UserDoesntExist)
                    }
                    UserVerificationError::DatabaseError(err) => {
                        return Err(UserLoginError::DatabaseError(err))
                    }
                    UserVerificationError::HashingFailure(err) => {
                        return Err(UserLoginError::HashingFailure(err))
                    }
                    UserVerificationError::UserIdParseFailure(err) => {
                        return Err(UserLoginError::UserIdParseFailure(err))
                    }
                },
            }
        }
        UserVerificationMethod::TwoFactor(twofactor_login_request) => {
            // check user exists
            let user_res = get_user(&twofactor_login_request.username).await;
            let user: Users::Model;
            match user_res {
                Ok(user_model) => user = user_model,
                Err(err) => match err {
                    UserGetError::UserDoesntExist => return Err(UserLoginError::UserDoesntExist),
                    UserGetError::DatabaseError(err) => {
                        return Err(UserLoginError::DatabaseError(err))
                    }
                    UserGetError::UserIdParseFailure(err) => {
                        return Err(UserLoginError::UserIdParseFailure(err))
                    }
                },
            }

            // check token exists
            let res = connect().await;
            let conn: DatabaseConnection;
            match res {
                Ok(res) => {
                    conn = res;
                }
                Err(err) => {
                    return Err(UserLoginError::DatabaseError(
                        sea_orm::DbErr::ConvertFromU64(err),
                    ))
                }
            }
            let now = OffsetDateTime::now_utc();
            let now = Some(PrimitiveDateTime::new(now.date(), now.time())).unwrap();
            let token_res = Tokens::Entity::find()
                .filter(
                    Tokens::Column::TokenId.eq(twofactor_login_request.session_login_attempt_id),
                )
                .filter(Tokens::Column::UserId.eq(&user.user_id))
                .filter(Tokens::Column::ExpirationDate.gt(now))
                .one(&conn)
                .await;

            let token: Tokens::Model;
            match token_res {
                Ok(token_res) => match token_res {
                    Some(token_res) => token = token_res,
                    None => return Err(UserLoginError::NoSuchTwoFactorSessionToken),
                },
                Err(err) => return Err(UserLoginError::DatabaseError(err)),
            }

            // already authed, you can have it back i guess?
            if token.is_two_factor_token == 0 {
                match Uuid::from_str(&token.token_id) {
                    Ok(token_id) => return Ok(token_id),
                    Err(err) => return Err(UserLoginError::TokenParseFailure(err)),
                };
            }

            // Do whatever to validate OTP I guess?
            match verify_twofac(user.to_owned(), twofactor_login_request.otp.to_owned()).await {
                Ok(res) => {
                    if res {
                        // Create normal auth token and return
                        match create_auth_token(
                            Uuid::from_str(&user.user_id).unwrap(),
                            AuthTokenCreateType::New,
                        )
                        .await
                        {
                            Ok(res) => {
                                // delete 2fac session token
                                let delete_res = Tokens::Entity::delete_by_id(token.token_id)
                                    .exec(&conn)
                                    .await;
                                match delete_res {
                                    Ok(_) => (),
                                    Err(err) => {
                                        dbg! {"error deleting 2fac session token {}",err};
                                    }
                                }
                                Ok(res)
                            }
                            Err(err) => match err {
                                AuthTokenCreationFailure::DatabaseError(err) => {
                                    return Err(UserLoginError::DatabaseError(err))
                                }
                                AuthTokenCreationFailure::TokenParseFailure(err) => {
                                    return Err(UserLoginError::TokenParseFailure(err))
                                }
                                AuthTokenCreationFailure::NoSuchTwoFactorToken => {
                                    return Err(UserLoginError::NoSuchTwoFactorSessionToken)
                                }
                            },
                        }
                    } else {
                        return Err(UserLoginError::IncorrectTwoFactor);
                    }
                }
                Err(err) => match err {
                    TwoFactorVerifyErr::TwoFactorNotEnabled => {
                        return Err(UserLoginError::NoSuchTwoFactorSessionToken);
                    }
                    _ => return Err(UserLoginError::VerificationFailed),
                },
            }
        }
    }
}

// Create new token or update current to have new expiry time
async fn create_auth_token(
    user_id: Uuid,
    token_type: AuthTokenCreateType,
) -> Result<Uuid, AuthTokenCreationFailure> {
    let conn = connect().await;
    match conn {
        Ok(conn) => {
            match token_type {
                AuthTokenCreateType::TwoFactor => {
                    let tokenid = Uuid::new_v4();
                    let expiry: OffsetDateTime = OffsetDateTime::now_utc() + (5 * Duration::MINUTE);
                    let time = Some(PrimitiveDateTime::new(expiry.date(), expiry.time())).unwrap();
                    let new_token = Tokens::ActiveModel {
                        token_id: Set(tokenid.to_string()),
                        user_id: Set(user_id.to_string()),
                        expiration_date: Set(time),
                        is_two_factor_token: Set(1),
                    };

                    let res = new_token.insert(&conn).await;
                    match res {
                        Ok(res) => match Uuid::parse_str(&res.token_id) {
                            Ok(token) => return Ok(token),
                            Err(err) => {
                                return Err(AuthTokenCreationFailure::TokenParseFailure(err))
                            }
                        },
                        Err(err) => return Err(AuthTokenCreationFailure::DatabaseError(err)),
                    }
                }
                // Extend duration the existing token that's being used for this session
                AuthTokenCreateType::ReAuthenticate(id) => {
                    let res = Tokens::Entity::find_by_id(id.to_string()).one(&conn).await;
                    match res {
                        Ok(token) => match token {
                            Some(token) => {
                                let expiry = OffsetDateTime::now_utc() + Duration::WEEK;
                                let time =
                                    Some(PrimitiveDateTime::new(expiry.date(), expiry.time()))
                                        .unwrap();
                                let mut token: Tokens::ActiveModel = token.into();
                                token.expiration_date = Set(time);
                                let token = token.update(&conn).await;

                                match token {
                                    Ok(token) => match Uuid::parse_str(&token.token_id) {
                                        Ok(token) => return Ok(token),
                                        Err(err) => {
                                            return Err(
                                                AuthTokenCreationFailure::TokenParseFailure(err),
                                            )
                                        }
                                    },
                                    Err(err) => {
                                        return Err(AuthTokenCreationFailure::DatabaseError(err))
                                    }
                                }
                            }
                            None => return Err(AuthTokenCreationFailure::NoSuchTwoFactorToken),
                        },
                        Err(err) => return Err(AuthTokenCreationFailure::DatabaseError(err)),
                    }
                }
                AuthTokenCreateType::New => {
                    let tokenid = Uuid::new_v4();
                    let expiry = OffsetDateTime::now_utc() + Duration::WEEK;
                    let time = Some(PrimitiveDateTime::new(expiry.date(), expiry.time())).unwrap();
                    let new_token = Tokens::ActiveModel {
                        token_id: Set(tokenid.to_string()),
                        user_id: Set(user_id.to_string()),
                        expiration_date: Set(time),
                        is_two_factor_token: Set(0),
                    };

                    let res = new_token.insert(&conn).await;
                    match res {
                        Ok(res) => match Uuid::parse_str(&res.token_id) {
                            Ok(token) => return Ok(token),
                            Err(err) => {
                                return Err(AuthTokenCreationFailure::TokenParseFailure(err))
                            }
                        },
                        Err(err) => return Err(AuthTokenCreationFailure::DatabaseError(err)),
                    }
                }
            }
        }
        Err(err) => {
            return Err(AuthTokenCreationFailure::DatabaseError(
                sea_orm::DbErr::ConvertFromU64(err),
            ))
        }
    }
}

pub async fn init_twofac(mut user: Users::Model) -> Result<String, TwoFactorInitErr> {
    // don't override the second factor if twofac is on
    if user.two_factor_enabled == 1 {
        dbg! {"Two factor already enabled"};
        return Err(TwoFactorInitErr::AlreadyEnabled);
    }

    let secret = Secret::default();
    let twofac = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("Rstmgmt".to_string()),
        user.username.to_owned(),
    )
    .unwrap();

    user.two_factor_secret = Some(secret.to_string());
    let code = twofac.get_qr();
    match code {
        Ok(code) => return Ok(code),
        Err(err) => return Err(TwoFactorInitErr::QrCreationFailure(err)),
    }
}

pub async fn enable_twofac(
    mut user: Users::Model,
    otp: String,
) -> Result<(), TwoFactorVerifyToEnableFailure> {
    if Some(user.two_factor_secret.to_owned()).is_none() {
        return Err(TwoFactorVerifyToEnableFailure::TwoFactorNotCreated);
    }
    if user.two_factor_enabled == 1 {
        return Err(TwoFactorVerifyToEnableFailure::TwoFactorAlreadyEnabled);
    }
    let now = OffsetDateTime::now_utc();
    if PrimitiveDateTime::new(now.date(), now.time()) > user.two_factor_enable_date.unwrap() {
        user.two_factor_secret = None;
        user.two_factor_enable_date = None;
        return Err(TwoFactorVerifyToEnableFailure::ValidationTimedOut);
    } else {
        match verify_twofac(user.to_owned(), otp).await {
            Ok(matches) => {
                if matches {
                    user.two_factor_enabled = 1;
                    return Ok(());
                } else {
                    return Err(TwoFactorVerifyToEnableFailure::TwoFactorIncorrect);
                }
            }
            Err(err) => match err {
                TwoFactorVerifyErr::TwoFactorNotEnabled => {
                    return Err(TwoFactorVerifyToEnableFailure::TwoFactorNotCreated)
                }
                TwoFactorVerifyErr::SystemTimeError(err) => {
                    return Err(TwoFactorVerifyToEnableFailure::SystemTimeError(err))
                }
                TwoFactorVerifyErr::TotpErr(err) => {
                    return Err(TwoFactorVerifyToEnableFailure::TotpErr(err))
                }
            },
        }
    }
}

async fn verify_twofac(user: Users::Model, otp: String) -> Result<bool, TwoFactorVerifyErr> {
    if Some(user.two_factor_secret.to_owned()).is_none() {
        return Err(TwoFactorVerifyErr::TwoFactorNotEnabled);
    }

    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        user.two_factor_secret.unwrap().as_bytes().to_vec(),
        Some("Rstmgmt".to_string()),
        user.username,
    );

    match totp {
        Ok(totp) => {
            let res = totp.check_current(&otp);
            match res {
                Ok(matches) => {
                    return Ok(matches);
                }
                Err(err) => return Err(TwoFactorVerifyErr::SystemTimeError(err)),
            }
        }
        Err(err) => return Err(TwoFactorVerifyErr::TotpErr(err)),
    }
}

pub async fn verify_session_token(session_token: Uuid) -> Result<(), VerifySessionTokenError> {
    let conn = connect().await;
    match conn {
        Ok(conn) => {
            let token = Tokens::Entity::find_by_id(session_token.to_string())
                .one(&conn)
                .await;
            match token {
                Ok(token) => match token {
                    Some(token) => {
                        let now = OffsetDateTime::now_utc();
                        if Some(PrimitiveDateTime::new(now.date(), now.time())).unwrap()
                            < token.expiration_date
                        {
                            if token.is_two_factor_token == 0 {
                                return Ok(());
                            } else {
                                return Err(VerifySessionTokenError::NoSuchToken);
                            }
                        }
                    }
                    None => return Err(VerifySessionTokenError::NoSuchToken),
                },
                Err(err) => return Err(VerifySessionTokenError::DatabaseError(err)),
            }
        }
        Err(err) => {
            return Err(VerifySessionTokenError::DatabaseError(
                sea_orm::DbErr::ConvertFromU64(err),
            ))
        }
    }
    todo! {}
}
