# Build the project with cargo in release mode
cargo build --release

# Change directory to C:\Users\enty
Set-Location -Path C:\Users\enty

# Run UPX to compress the executable
.\upx.exe --best --lzma 'C:\Users\enty\Hosting\FIVEM\OwnStuff\JOURNEY\AuthPY\rsping\NEW\target\release\meowping.exe'

# Change directory back to the project folder
Set-Location -Path 'C:\Users\enty\Hosting\FIVEM\OwnStuff\JOURNEY\AuthPY\rsping\NEW'
