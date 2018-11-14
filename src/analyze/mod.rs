mod graph;
mod helper;
mod join;

pub use self::graph::{generate_distance, testing};
pub use self::helper::load_data;
pub use self::join::join_data;

pub enum Steps {
    JoinData,
    Testing,
    DistanceMatrix,
}

pub fn run(step: &Steps) {
    match step {
        Steps::JoinData => join_data(false),
        Steps::DistanceMatrix => generate_distance(),
        Steps::Testing => testing(),
    }
}
