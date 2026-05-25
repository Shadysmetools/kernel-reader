@echo off
REM Build user-mode client. Run from a "x64 Native Tools Command Prompt for VS".
pushd "%~dp0\client"
cl /nologo /EHsc /W3 /O2 /std:c++17 client.cpp /link /OUT:client.exe
popd
