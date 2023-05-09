use rstmgmt::do_migration;
use std::io;

#[tokio::main]
async fn main() {
    do_migration().await;
    println!("Hello, world!");

    println!("Enter a username:");
    let mut username = String::new();
    io::stdin()
        .read_line(&mut username)
        .expect("failed to read stdin");
    let _trimmed_username = username.trim();

    println!("Enter a password:");
    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .expect("failed to read stdin");
    let _trimmed_password = password.trim();

    /*
    let res: Result<_, _> = create_user(&UsernameAndPassword {
        username: trimmed_username.to_string(),
        password: trimmed_password.to_string(),
    })
    .await;
    match res {
        Ok(userid) => {
            dbg! {userid};
        }
        Err(err) => match err {
            UserCreationError::UserAlreadyExists => {
                dbg! {"User already exists"};
                ()
            }
            UserCreationError::InvalidPassword(_) => {
                dbg! {"Password does not meet criterion"};
                ()
            }
            UserCreationError::DatabaseError(_) => {
                dbg! {"database error occured"};
                ()
            }
            UserCreationError::HashingFailure(_) => {
                dbg! {"password hashing error occured"};
                ()
            }
        },
    }*/
}
