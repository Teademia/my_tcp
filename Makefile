all:
	@ gcc main.c -lpcap -o main

clean:
	@rm main