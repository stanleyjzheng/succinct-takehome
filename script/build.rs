use sp1_helper::build_program_with_args;

fn main() {
    build_program_with_args("../program", Default::default());
    build_program_with_args(
        "/Users/terbi/Desktop/sp1/examples/fibonacci/program",
        Default::default(),
    );
}
