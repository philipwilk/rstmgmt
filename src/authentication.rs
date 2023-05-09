use std::str::FromStr;

use crate::database::connect;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use entity::{tokens as Tokens, users as Users};

use rand_core::OsRng;
use sea_orm::error::DbErr;
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;

#[derive(Debug, PartialEq, PartialOrd)]
pub struct UsernameAndPassword {
    pub username: String,
    pub password: String,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct TwoFactorLoginRequest {
    pub username: String,
    pub id: Uuid,
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
    NoSuchTwoFactorToken,
    TwoFactorNeeded(Uuid), // reserved
    AccountLocked,         // reserved
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
                .filter(Tokens::Column::TokenId.eq(twofactor_login_request.id))
                .filter(Tokens::Column::UserId.eq(&user.user_id))
                .filter(Tokens::Column::ExpirationDate.lt(now))
                .one(&conn)
                .await;

            let token: Tokens::Model;
            match token_res {
                Ok(token_res) => match token_res {
                    Some(token_res) => token = token_res,
                    None => return Err(UserLoginError::NoSuchTwoFactorToken),
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

            // Create normal auth token and return
            match create_auth_token(
                Uuid::from_str(&user.user_id).unwrap(),
                AuthTokenCreateType::New,
            )
            .await
            {
                Ok(res) => Ok(res),
                Err(err) => match err {
                    AuthTokenCreationFailure::DatabaseError(err) => {
                        return Err(UserLoginError::DatabaseError(err))
                    }
                    AuthTokenCreationFailure::TokenParseFailure(err) => {
                        return Err(UserLoginError::TokenParseFailure(err))
                    }
                    AuthTokenCreationFailure::NoSuchTwoFactorToken => {
                        return Err(UserLoginError::NoSuchTwoFactorToken)
                    }
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
