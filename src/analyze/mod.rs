mod helper;
mod join;
mod paths;
mod graph;

pub use self::helper::load_data;

use self::join::join_data;
use self::paths::check_paths;
use self::graph::graph_info;

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
        Steps::Testing => graph_info(),
        _ => {}
    }
}
