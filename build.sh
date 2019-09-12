#!/bin/bash

set -e -o xtrace

which go 2>/dev/null 1>/dev/null
if [[ $? -ne 0 ]]; then
    echo "error: failed to find go binary- do you have Go 1.13 installed?"
    exit 1
fi

GOVERSION=`go version`
if [[ $GOVERSION != *"go1.13"* ]]; then
    echo "error: Go version is not 1.13 (was $GOVERSION)"
    exit 1
fi

export PYTHONPATH=`pwd`/src/github.com/go-python/gopy/

echo "cleaning up output folder"
rm -frv gosnmp_traps_python/*.pyc
rm -frv gosnmp_traps_python/py2/*
echo ""

if [[ "$1" == "clean" ]]; then
    exit 0
fi

if [[ "$1" != "fast" ]]; then
    echo "getting assert"
    go get -v -u github.com/stretchr/testify/assert
    echo ""

    echo "getting gosnmp"
    go get -v -u github.com/ftpsolutions/gosnmp
    echo ""

    echo "building gosnmp"
    go build -x -a github.com/ftpsolutions/gosnmp
    echo ""

    echo "getting gopy"
    go get -v -u github.com/go-python/gopy@v0.3.1
    echo ""

    echo "installing gopy"
    go install -i github.com/go-python/gopy
    echo ""

    echo "building gopy"
    go build -x -a github.com/go-python/gopy
    echo ""

    echo "building gosnmp_traps_python"
    go build -x -a gosnmp_traps_python/gosnmp_traps_python_go
    echo ""

    # Use a specific version!
    echo "getting goimports"
    go get golang.org/x/tools/cmd/goimports@v0.0.0-20190910044552-dd2b5c81c578
fi

echo "installing pybindgen - required for gopy"
pip install pybindgen==0.20.0

echo "build gosnmp_traps_python bindings for py2"
./gopy build -output="gosnmp_traps_python/py2" -symbols=true -vm=$(which python) gosnmp_traps_python/gosnmp_traps_python_go
echo ""

# Yep - this is highly questionable
# This requires an entry in LD_LIBRARY_PATH to work
SHARED_OBJ_DIR=/usr/local/lib/gopy/
echo "copying shared objects to ${SHARED_OBJ_DIR}"
mkdir -p ${SHARED_OBJ_DIR}
cp gosnmp_traps_python/py2/gosnmp_traps_python_go_go.so ${SHARED_OBJ_DIR}

# gopy doesn't seem to support Python3 as yet
# echo "build gosnmp_traps_python bindings for py3"
# ./gopy bind -lang="py3" -output="gosnmp_traps_python/py3" -symbols=true -work=false gosnmp_traps_python
# echo ""

#echo "build gosnmp_traps_python bindings for cffi"
#./gopy bind -api="cffi" -output="gosnmp_traps_python/cffi" -symbols=true -work=false gosnmp_traps_python
#echo ""

echo "cleaning up"
find . | grep -E "(__pycache__|\.pyc|\.pyo$)" | xargs rm -rf
echo ""
