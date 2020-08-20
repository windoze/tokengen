#!/bin/sh

cd "`dirname $0`"

dotnet publish -r osx-x64  -c Release /p:PublishSingleFile=true
