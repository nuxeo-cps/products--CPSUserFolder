@echo off

set STARTDIR=%cd%
:STARTLOOP
set CURDIR=%cd%
if exist z2.py GOTO HOMEFOUND
cd ..
set THISDIR=%cd%
if %CURDIR%==%THISDIR% goto NOHOMEFOUND
GOTO STARTLOOP

GOTO EXIT
:HOMEFOUND

if not "%PYTHON%"=="" set USEPYTHON=%PYTHON%
if "%PYTHON%"=="" set USEPYTHON=%cd%\bin\python
if "%SOFTWARE_HOME%"=="" set SOFTWARE_HOME=%cd%\lib\python

cd %STARTDIR%

%USEPYTHON% runalltests.py
GOTO EXIT

:NOHOMEFOUND
echo Could not found ZOPE installation
GOTO EXIT

:EXIT
cd %STARTDIR%



