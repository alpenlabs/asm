use sp1_build::build_program;

fn main() {
    build_program("../../guest-builder/sp1/guest-asm");
    build_program("../../guest-builder/sp1/guest-moho");
}
