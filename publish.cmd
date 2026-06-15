@echo off
rem Builds the portable single file release into .\publish
rem Run from the project folder. Requires .NET SDK 10.0.301 or newer.
rem ClamHub.ico is embedded as the EXE icon and also copied next to the EXE
rem so the Windows context menu entry can reference it.

dotnet publish ClamHub.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o publish

echo.
echo Done. Copy the ClamAV folder next to publish\ClamHub.exe before first run.
pause
