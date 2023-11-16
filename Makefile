all:
	$(MAKE) -C ipdbg all
	cp ipdbg/build/lib.*/ipdbg.*.so .

clean:
	$(MAKE) -C ipdbg clean
	rm ipdbg.*.so
