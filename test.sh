function clean {
	sleep 1s
	fusermount -u ./fat_mount
	fusermount -u ./fuse
	sleep 1s

	rm -r ./fat_mount
	rm -r ./tmp
}

function check {

	mkdir ./tmp >>/dev/null 2>&1
	mkdir ./fat_mount >>/dev/null 2>&1

	echo "> ./virtual_fat $1 ./fuse" >> log.txt
	./virtual_fat $1 ./fuse >>log.txt 2>&1
	if [ $? -ne 0 ]; then
		echo "./virtual_fat failed (check log.txt)"
		clean
		return
	fi

	echo "> dosfsck -nv ./fuse/vfat" >> log.txt
	dosfsck -nv ./fuse/vfat >>log.txt 2>&1
	if [ $? -ne 0 ]; then
		echo "filesystem is not valid (check log.txt)"
		clean
		return
	fi

	echo "> fusefat -o ro ./fuse/vfat ./fat_mount" >> log.txt
	fusefat -o ro ./fuse/vfat ./fat_mount >>log.txt 2>&1
	if [ $? -ne 0 ]; then
		echo "failed to mount filesystem (check log.txt)"
		clean
		return
	fi

	echo "> diff -qr ./fat_mount ./tmp" >> log.txt
	diff -qr ./fat_mount ./tmp >>log.txt 2>&1
	if [ $? -ne 0 ]; then
		echo "files differ (check log.txt)"
		clean
		return
	fi

	clean
	echo "test succeeded"
}

echo "" &> log.txt
check data/1.xml
check data/2.xml
check data/3.xml
check data/4.xml
#check data/5.xml #creates A LOT of temporary data
#check data/6.xml #creates A LOT of temporary data
check data/7.xml

