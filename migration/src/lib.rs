pub use sea_orm_migration::prelude::*;

mod m20230429_214129_users;
mod m20230429_214317_tokens;

#[derive(Iden)]
pub enum Uuid {
    Uuid,
}

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230429_214129_users::Migration),
            Box::new(m20230429_214317_tokens::Migration),
        ]
    }
}
