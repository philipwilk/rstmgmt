mod authentication;
mod database;

pub use authentication::{create_user, login_user, UserCreationError, UsernameAndPassword};

use migration::{Migrator, MigratorTrait};

pub async fn do_migration() {
    let connection = database::connect().await.unwrap();
    Migrator::up(&connection, None).await.unwrap();
}
