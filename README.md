# About
This is a program/library to emulate a read-only FAT (FAT16 or FAT32) file-system.  
It does this without requiring physical storage for the entire disk image.  
The parameters of the file-system can be automatically determined based on the requirements or they can be specified by the user.

# How to build and test
## Linux
It is easiest to test the library on a linux machine.  
To build it make sure you have libfuse and libmxml installed (you can also use libxml2 but the wrapper is not complete and will likely stay that way because using libxml2 creates a large binary which is not desireable on android). 
to install the required packages on debian machines you can use:  
`sudo apt-get install libfuse2 libfuse-dev libmxml1 libmxml-dev`

As the above line installs libfuse2 but the android build uses libfuse3 the file virtual_fat.c needs to be changed slightly. It should be sufficient to replace the first line `#define FUSE_USE_VERSION 30` to `#define FUSE_USE_VERSION 26`  
To make debugging easier the parameters for fuse_main should also be changed slightly:
search for fuse_argv and replace the definition with 
`char *fuse_argv[] = {"virtual_fat", "-f", "-s", fuse_dir};`
This ensures that the program is not daemonized and single threaded.

To compile it you can use:
`gcc -std=c99 -Ilib -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 virtual_fat.c lib/bootsector.c lib/directory_tree.c lib/minixml_parser.c lib/tree.c -o virtual_fat -lmxml -lfuse`

If you want to test the code in 32bit mode (which makes sense because most arm processors run in 32bit mode) on a 64bit machine you will have to recompile libfuse and minixml and link them.

`dosfsck` is one of the most useful tools for debugging the generated file-system.
The output when using the `-v` option is often easier to understand than a hex-dump.

## Android

To compile for android you can use the provided makefile (Android.mk).  
it should be noted that the Android makefile is intended for use with Android studio and the app (it copies the result to the appropriate folder for the IDE).

# Usage and file format
## Usage
The intended usage is `virtual_fat <config_file> <mount-point>`
The config file must be an xml file as described below. The mount point should be an empty folder (it will be created if it does not exist).

## File format
The best way to describe the file format is by showing an example:
```
<?xml version="1.0" encoding="UTF-8"?>
<fs>
    <directory name="folder" >
        <directory name="subfolder">
            <entry path="file_1.txt" recursive="true"/>
        </directory>
        <entry path="actual_folder" recursive="true"/>
    </directory>
</fs>
```
### <fs>
The root node `<fs>` can have the following (optional) attributes. If an attribute is omitted its value will be determined based on the content of the file-system:  
`oem_name` can be used to set the corresponding field of the boot sector. It can be up to 8 characters long The default is "MSWIN4.1"  
`bytes_per_sector=<512|1024|2048|4096>` sets the size of one cluster. Most storage mediums and formatting tools use 512 for this value.  
`sectors_per_cluster=<1|2|4|8|16|32|64|128>` sets the size of one cluster in multiples of the sector size (see https://technet.microsoft.com/en-us/library/cc938438.aspx for commonly used values).  
`num_FATs` can be used to set the number of File Allocation Tables. Any value greater than 0 is valid. The default value is 2.  
`num_root_entries` only useful for FAT16. It must be value such that `num_root_entries*32` is a multiple of `bytes_per_sector`. The default is 512.  
`type=<FAT16|FAT32>` can be used to manually specify the type. keep in mind that depending on the size of the files on the drive it might be impossible to fulfil this request.  
`allow_unsupported_size=<true|false>` The FAT specification states that 'bytes_per_sector*sectors_per_cluster' must not be greater than 64k. This implementation sets this limit lower at 32k. If you know what you are doing you can use this value to ignore this check (so you can have clusters that are greater than 32k). 

### <directory>
represents a virtual folder on the drive (i.e a folder that does not exist on the storage where the files are). You must set a name for this folder using the `name`-attribute.

### <entry>
entries represent files or folders on the actual backing file-system. 
The attribute 'recursive' is used to include all subfolders and files if the given `path` is a directory.

# Limitations 
There is no write support (yet?).  
FAT12 is not implemented.  
