BUILD_DIR := ./build
HEADER_DIR := ./header
SOURCE_DIR := ./source

reall : clean all

all : firewall

firewall : main.o packet.o
	g++ -g -o ${BUILD_DIR}/firewall ${BUILD_DIR}/main.o ${BUILD_DIR}/packet.o -lpcap -lnetfilter_queue

main.o : makeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/main.o ${SOURCE_DIR}/main.cpp

packet.o : makeBuildFolder
	g++ -g -c -o ${BUILD_DIR}/packet.o ${SOURCE_DIR}/packet.cpp

makeBuildFolder : 
	mkdir -p ${BUILD_DIR}

clean :
	rm -f ${BUILD_DIR}/*
