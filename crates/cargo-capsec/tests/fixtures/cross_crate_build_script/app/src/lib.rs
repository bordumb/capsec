use build_dep;

pub fn process(input: &str) -> Vec<String> {
    build_dep::parse(input)
}
