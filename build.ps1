# Build the project with cargo in release mode
cargo build --release

# Run UPX to compress the executable
.\upx.exe --best --lzma 'Path/to/your/meowping.exe'
