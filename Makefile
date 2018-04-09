CPP = g++

TARGET	= fpv_tx

DIR		= ./camera ./transfer ./ringbuf ./H264_camera

INC		= -I./include -I./transfer -I./ringbuf -I./H264_camera -I./camera

LDFLAGS = -L./lib -lx264 -lpthread -ldl -lm -lrt -lpcap
CFLAGS	= -g -Wall

OBJPATH	= ./objs

FILES	= $(foreach dir,$(DIR),$(wildcard $(dir)/*.cpp))

OBJS	= $(patsubst %.cpp,%.o,$(FILES))

all:$(OBJS) $(TARGET)

$(OBJS):%.o:%.cpp
	$(CPP) $(CFLAGS) $(INC) -c -o $(OBJPATH)/$(notdir $@) $< 

$(TARGET):$(OBJPATH)
	$(CPP) -o $@ $(OBJPATH)/*.o $(LDFLAGS)

#$(OBJPATH):
#	mkdir -p $(OBJPATH)

clean:
	-rm -f $(OBJPATH)/*.o
	-rm -f $(TARGET)