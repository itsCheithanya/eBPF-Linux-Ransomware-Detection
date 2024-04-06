#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>  // For sleep() function


int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <directory>\n", argv[0]);
    return 1;
  }


    // These are data types defined in the "dirent" header
    DIR *theFolder = opendir(argv[1]);
    struct dirent *next_file;
    char filepath[256];

    while ( (next_file = readdir(theFolder)) != NULL )
    {
        // build the path for each file in the folder
        sprintf(filepath, "%s/%s", argv[1], next_file->d_name);
        printf("%s",filepath);
        remove(filepath);
    }
    // sleep(60);
    closedir(theFolder);
    return 0;
}