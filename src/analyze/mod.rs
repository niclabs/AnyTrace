mod join;
pub use self::join::join_data;

pub enum Steps {
    JoinData,
}

pub fn run(step: Steps) {
    match step {
        Steps::JoinData => join_data(true),
    }
}
