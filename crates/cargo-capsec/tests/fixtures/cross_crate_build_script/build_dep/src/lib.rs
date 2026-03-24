pub fn parse(data: &str) -> Vec<String> {
    data.lines().map(String::from).collect()
}
