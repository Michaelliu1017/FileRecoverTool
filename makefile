
# Makefile 11/24/24
CC = gcc

# 编译指令
CFLAGS = -Wall -g -lcrypto

#可执行文件名
TARGET = FileRecoverTool

# source文件
SRC = Main.c  

#生成exec
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -pthread

# 清理
clean:
	rm -f $(TARGET)
