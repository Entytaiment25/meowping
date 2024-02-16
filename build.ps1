# Build the project with cargo in release mode
cargo build --release

# Change directory to C:\Users\enty
Set-Location -Path C:\Users\enty

# Run UPX to compress the executable
.\upx.exe --best --lzma 'C:\Users\enty\Documents\Hosting\FIVEM\OwnStuff\JOURNEY\AuthPY\MeowPing\NEW\target\release\meowping.exe'

# Change directory back to the project folder
Set-Location -Path 'C:\Users\enty\Documents\Hosting\FIVEM\OwnStuff\JOURNEY\AuthPY\MeowPing\NEW'
