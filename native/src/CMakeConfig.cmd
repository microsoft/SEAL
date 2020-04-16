@echo off

rem Copyright (c) Microsoft Corporation. All rights reserved.
rem Licensed under the MIT license.

setlocal

rem The purpose of this script is to have CMake generate config.h for use by Microsoft SEAL.
rem We assume that CMake was installed with Visual Studio, which should be the default
rem when the user installs the "Desktop Development with C++" workload.

set VSVERSION=%~1
set PROJECTCONFIGURATION=%~2
set PROJECTPLATFORM=%~3
set VSDEVENVDIR=%~4
set INCLUDEPATH=%~5
set LIBRARYPATH=%~6

echo Configuring Microsoft SEAL through CMake

if not exist "%VSDEVENVDIR%" (
	rem We may be running in the CI server. Try a standard VS path.
	echo Did not find VS at provided location: "%VSDEVENVDIR%".
	echo Trying standard location.
	set VSDEVENVDIR="C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\IDE"
)

set VSDEVENVDIR=%VSDEVENVDIR:"=%
set CMAKEPATH=%VSDEVENVDIR%\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe

if not exist "%CMAKEPATH%" (
	echo ******************************************************************************************************************
	echo **  Did not find CMake at "%CMAKEPATH%"
	echo **  Please make sure "Visual C++ Tools for CMake" are enabled in the "Desktop development with C++" workload.
	echo ******************************************************************************************************************
	exit 1
)

echo Found CMake at %CMAKEPATH%

rem Identify Visual Studio version and set CMake generator accordingly.
set CMAKEGEN=""
if "%VSVERSION%"=="15.0" (
	set CMAKEGEN="Visual Studio 15 2017"
) else if "%VSVERSION%"=="16.0" (
	set CMAKEGEN="Visual Studio 16 2019"
) else (
	echo ***************************************************
	echo **  Unsupported Visual Studio version "%VSVERSION%"
	echo ***************************************************
	exit 1
)

rem Download Microsoft GSL
set MSGSLCONFIGDIR="..\..\thirdparty\msgsl\.config\%VSVERSION%\%PROJECTPLATFORM%"
cd %~dp0
if not exist %MSGSLCONFIGDIR% (
	mkdir %MSGSLCONFIGDIR%
)
cd %MSGSLCONFIGDIR%
"%CMAKEPATH%" ..\..\.. -G %CMAKEGEN% -A %PROJECTPLATFORM%
"%CMAKEPATH%" --build . --config "%PROJECTCONFIGURATION%"

rem Copy Microsoft GSL header files into the local source directory
robocopy ..\..\..\src\include %~dp0 /s

rem Download and build ZLIB
set ZLIBCONFIGDIR="..\..\thirdparty\zlib\.config\%VSVERSION%\%PROJECTPLATFORM%"
cd %~dp0
if not exist %ZLIBCONFIGDIR% (
	mkdir %ZLIBCONFIGDIR%
)
cd %ZLIBCONFIGDIR%
"%CMAKEPATH%" ..\..\.. -G %CMAKEGEN% -A %PROJECTPLATFORM%           ^
	-DZLIB_PLATFORM="%PROJECTPLATFORM%"

"%CMAKEPATH%" --build . --config "%PROJECTCONFIGURATION%"

rem Configure Microsoft SEAL
set CONFIGDIR="..\..\.config\%VSVERSION%\%PROJECTPLATFORM%"
cd %~dp0
if not exist %CONFIGDIR% (
	mkdir %CONFIGDIR%
)
cd %CONFIGDIR%
echo Running CMake configuration in %cd%

"%CMAKEPATH%" ..\..\.. -G %CMAKEGEN% -A %PROJECTPLATFORM%           ^
	-DALLOW_COMMAND_LINE_BUILD=1                                    ^
	-DCMAKE_BUILD_TYPE="%PROJECTCONFIGURATION%"                     ^
	-DBUILD_SHARED_LIBS=OFF                                         ^
	-DSEAL_USE_MSGSL=ON                                             ^
	-DSEAL_USE_ZLIB=ON                                              ^
	-DSEAL_BUILD_TESTS=OFF                                          ^
	-DSEAL_BUILD_EXAMPLES=OFF                                       ^
	-DSEAL_BUILD_SEAL_C=OFF                                         ^
	--no-warn-unused-cli
