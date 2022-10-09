set -x
g++ -o libmaptools.so -g -O0 --std=c++11 -shared -fPIC -ldl maptools.cpp
g++ -o huge_demo -g -O0 --std=c++11 -L. -ldl -lmaptools huge_demo.cpp

