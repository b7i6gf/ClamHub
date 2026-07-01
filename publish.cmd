@echo off
rem Builds the portable single file release into .\publish
rem Run from the project folder. Requires .NET SDK 10.0.301 or newer.


dotnet publish ClamHub.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o publish

echo.
echo Done. The executable can be found under .\publish\ClamHub.exe
pause
