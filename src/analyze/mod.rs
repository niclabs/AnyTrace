mod graph;
mod helper;
mod join;
mod latency;
//mod paths;
mod compare;

pub use self::helper::load_data;

use self::graph::graph_info;
use self::join::join_data;
use self::latency::check_latency;
//use self::paths::check_paths;
use self::compare::compare_joins;

pub enum Steps {
    JoinData,
    Testing,
    DistanceMatrix,
    Paths,
    Latency,
    Compare,
}

pub fn run(step: &Steps) {
    match step {
        Steps::JoinData => join_data(true),
 //       Steps::Paths => check_paths(),
        Steps::Testing => graph_info(),
        Steps::Latency => check_latency(),
        Steps::Compare => compare_joins(),
        _ => {}
    }
}
