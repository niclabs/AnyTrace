mod helper;
mod join;
mod paths;

pub use self::helper::load_data;

use self::join::join_data;
use self::paths::check_paths;

pub enum Steps {
    JoinData,
    Testing,
    DistanceMatrix,
    Paths,
}

pub fn run(step: &Steps) {
    match step {
        Steps::JoinData => join_data(false),
        Steps::Paths => check_paths(),
        _ => {}
    }
}