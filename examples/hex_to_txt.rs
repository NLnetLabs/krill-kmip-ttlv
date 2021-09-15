#[cfg(not(feature = "high-level"))]
fn main() {
    unreachable!("This example requires the 'high-level' feature.");
}

#[cfg(feature = "high-level")]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: hex_to_text <path/to/ttlv_input_hex.txt>");
        std::process::exit(1);
    }

    let mut ttlv_hex_str = std::fs::read_to_string(&args[1]).expect("Failed to read the input file");

    for string_to_remove in [" ", "\n", r#"""#, ","] {
        ttlv_hex_str = ttlv_hex_str.replace(string_to_remove, "");
    }

    let ttlv_bin = hex::decode(ttlv_hex_str)
        .expect("Failed to parse the input file. Make sure it is in hex format, e.g. 42007A..");

    println!("{}", kmip_ttlv::PrettyPrinter::new().to_string(&ttlv_bin));
}
