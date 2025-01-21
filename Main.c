#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <ctype.h>

/* * * * * * * * * * * * * * * * *          
*       File Recever Tool        *
*  GUOLIANG LIU     24/Nov/24    *
*   M1 Completed                 *
*   M2 Completed                 *
*   M3 Completed                 *
*   M4 Completed                 *
*   M5 Completed                 *
*   M6 Completed                 *  
*   M7 7a Completed 7b Failed    *
*   M8 [X]                       *
* * * * * * * * * * * * * * * * */

unsigned char *SHA1(const unsigned char *d,size_t n, unsigned char *md);
#define ENTRY_SIZE 32
#define EOF_F 0x0FFFFFF8
 const char *sha_para;

//**************************************************************************************/
// 1) Boot Reader 
//**************************************************************************************/
int * bootReader(const char * disk, int cmd){
    
     int* boot_info = malloc(7 * sizeof(int));
      int fd = open(disk, O_RDWR); 
       unsigned char boot_sector[512];

    if (fd < 0) {
        perror("Error[1.1]: Fail to Open the Disk");
        exit(1);
    }else if (read(fd, boot_sector, 512) != 512) {
        perror("Error[1.2]: Fail to Read Boot");
        close(fd);
        exit(1);
    }
    // sector_bytesNum
    boot_info[0] = boot_sector[11] + (boot_sector[12] *256); 
    // rs_num
    boot_info[1] = boot_sector[14] + (boot_sector[15]*256); 
    // sector per FAT
    boot_info[2] = boot_sector[36] + (boot_sector[37]*256);  
    // sector per Cluster
    boot_info[3] = boot_sector[13];                        
    // FAT num
    boot_info[4] = boot_sector[16];                           
     // dir cluster
    boot_info[5] = boot_sector[44] | (boot_sector[45]*256); 
     // FAT offset
    boot_info[6] = boot_info[1] * boot_info[0];              
    
    if(cmd==1){
        //FS info
        printf("Number of FATs = %d\n", boot_info[4]);
         printf("Number of bytes per sector = %d\n",  boot_info[0]);
         printf("Number of sectors per cluster = %d\n", boot_info[3]);
        printf("Number of reserved sectors = %d\n",  boot_info[1]);
    }
    close(fd);
    return boot_info;
}



//**************************************************************************************/
// 2) SHA Sum Calculator 
//**************************************************************************************/
int SHAcomparator( const char * data){

        int flag=1;
       if (strlen(sha_para) != 40) {
        perror("[Error 2.1]: SHA INPUT IS ILLEGAL!!!");
        exit(0);
    }

       size_t len = strlen(data);  
        unsigned char hash[20];
        SHA1((unsigned char *)data, len, hash);

         unsigned char hash_para[20];
         for (int i = 0; i < 20; i++) {
        
        int high;
        if(!isdigit(sha_para[2*i])){
             high = tolower(sha_para[2*i])-'a'+10;
        }else{
             high = sha_para[2*i]-'0'; 
        }
        int low;
        if(!isdigit(sha_para[2*i + 1])){
             low = tolower(sha_para[2*i + 1])-'a'+10;
        }else{
             low = sha_para[2*i + 1]-'0';
        }   
        
         hash_para[i]=high*16+low;
    }
     
         if(0){
              printf("SHA-1 hash : ");
               for (int i = 0; i < 20; i++) {
                  printf("%02x", hash[i]);
              }
              printf("\n");

              printf("SHA-1 hash std: ");
              for (int i = 0; i < 20; i++) {
                 printf("%02x", hash_para[i]);
              }
              printf("\n");

              }
  

              for(int i=0;i<20;i++){
                   if(hash[i]!=hash_para[i]){
                       flag=0;
                   }
         }

         return flag;

}

//**************************************************************************************/
// 3) Ambiguity File Check 
//**************************************************************************************/
int multiFileChecker(const char* disk, const char *fileName){

    int fd = open(disk, O_RDWR); 
    int flag=-1;
    int count_a=0;
     int *boot_info = bootReader(disk,0);
    
    int sector_bytesNum = boot_info[0];
    int rs_num = boot_info[1];
    int fat_sec_num = boot_info[2];
    int cluster_size = boot_info[3];
    int fat_num = boot_info[4];
    int root_dir_cluster = boot_info[5];
    int data_region_offset = (rs_num+fat_num*fat_sec_num)*sector_bytesNum;
    int root_dir_offset = data_region_offset+(root_dir_cluster - 2)*cluster_size*sector_bytesNum;

    unsigned char buffer[ENTRY_SIZE];
    
    lseek(fd, root_dir_offset, SEEK_SET);

    while (read(fd, buffer, ENTRY_SIZE) == ENTRY_SIZE) {
        
         if (buffer[0] == 0xE5) { 

            char df_name[13] = {0};
            strncpy(df_name, (char *)buffer + 1, 8); 
            for (int i = 7; i >= 0; i--) {
                if (df_name[i] == ' ') {
                    df_name[i] = '\0'; 
                }
            }

            if (buffer[8] != ' ') {
                //has ext 
                char cup[5] = "."; 
                strncat(cup, (char *)buffer + 8, 3); 
                strcat(df_name, cup); 
            }

            if (strcmp(df_name, fileName + 1) == 0) {
                 count_a++;
                 
                }
        }

    }
     if(count_a>1){
             flag=1;
             printf("%s: multiple candidates found\n",fileName);
        }

    close(fd);
    return flag;
}

//**************************************************************************************/
// 4) FAT Update 
//**************************************************************************************/
void FATupdate(int fd, int fat_entry_offset,int next_cluster){

    lseek(fd, fat_entry_offset, SEEK_SET);
     unsigned char fat_entry[4];
     int cup=next_cluster;
     fat_entry[0] = next_cluster % 256; 
    cup/=256;
    fat_entry[1] = cup % 256;  
    cup/=256;
     fat_entry[2] = cup % 256; 
    cup/=256;
    fat_entry[3] = cup % 256; 

    write(fd, fat_entry, 4);
}

//**************************************************************************************/
// 5) Next Cluster Finder 
//**************************************************************************************/
unsigned char* ClusterFinder(int fd, int start_cluster, int file_size,int data_region_offset, int cluster_size, int sector_bytesNum, int fat_table_offset){

     unsigned char *file_content = malloc(file_size + 1); 
    int remaining_size = file_size; 
    int cluster_cup = start_cluster; 
    int byteRead=0;
    int cluster_byte=cluster_size * sector_bytesNum;

    while (remaining_size > 0) {
        
        int cluster_offset = data_region_offset + (cluster_cup-2) * cluster_byte;
        lseek(fd, cluster_offset, SEEK_SET);

        if(remaining_size>cluster_byte){
            byteRead=cluster_byte;
        }else{
            byteRead=remaining_size;
        }
        read(fd, file_content, byteRead);
        file_content+=byteRead;
        remaining_size -= byteRead;
        cluster_cup++; 
    }

    file_content[file_size]='\0'; 
    return file_content;
}

//**************************************************************************************/
// 6) List Root Directory 
//**************************************************************************************/
void listRootDir(const char *disk){
     int fd = open(disk, O_RDONLY);
    int *boot_info = bootReader(disk,0);
    int sector_bytesNum = boot_info[0];
    int rs_num = boot_info[1];
    int fat_sec_num =  boot_info[2];
    int cluster_size = boot_info[3]; 
    int fat_num =  boot_info[4]; 
    int root_dir_cluster = boot_info[5];
    int cluster_byte=cluster_size * sector_bytesNum;
    int offset_fat=rs_num*sector_bytesNum;
    //data Region
    int offset_r = (rs_num+fat_num*fat_sec_num) * sector_bytesNum;
    unsigned int cup_cluster = root_dir_cluster;
    int total= 0;


    while (cup_cluster < EOF_F) { 
        
         int cluster_offset=offset_r+(cup_cluster-2)*cluster_byte;
          lseek(fd, cluster_offset, SEEK_SET);
        int readSize=cluster_byte/ENTRY_SIZE;
       for (int i = 0; i < readSize; i++) {

            unsigned char buffer[ENTRY_SIZE];
            read(fd, buffer, ENTRY_SIZE);
              
            if (buffer[0] == 0x00) {
                 break;
             }else if (buffer[0] == 0xE5){
                 continue;
             }
        
         // File Extraction
            char filename[13] = {0};
             strncpy(filename, (char *)buffer, 8);
             for (int i = 0; i <= 7; i++) {
                  if(filename[i] == ' '){
                    filename[i] = '\0'; 
             } 
            }

        if(buffer[8]!=' '){
            strcat(filename, ".");
             for (int i = 8; i < 11; i++) {
                if (buffer[i] != ' ') {
                char ext_cup[2] = {buffer[i], '\0'};
                strcat(filename, ext_cup);
               }
            }  
        }
        
        // Dir Check
        unsigned char attributes = buffer[11];
        int is_directory;
        if ((attributes & 0x10)==0) {
            is_directory = 0; 
        } else {
            is_directory = 1; 
        }
        //cluster Check
        int start_cluster = buffer[26] + (buffer[27]*256);
        // File size Check
        int file_size = buffer[28] + (buffer[29]*256) + (buffer[30] *256) + (buffer[31]*256);

        if (is_directory) {
            printf("%s/ (starting cluster = %d)\n", filename, start_cluster);
        } else if (file_size > 0) {
            printf("%s (size = %d, starting cluster = %d)\n", filename, file_size, start_cluster);
        } else if(file_size == 0){
            printf("%s (size = 0)\n", filename);
        }else{
            printf("%s (size = ?)\n", filename);
        }
        total++;
       }
       // find next cluster
        int offset_fatEntry = offset_fat + (cup_cluster * 4);  
        unsigned char clusterEntry[4];
       lseek(fd, offset_fatEntry, SEEK_SET);
        read(fd, clusterEntry, 4);
        
        cup_cluster = clusterEntry[0] + (clusterEntry[1]*256) + (clusterEntry[2]*256*256) + (clusterEntry[3]*256*256*256);
    }

    printf("Total number of entries = %d\n", total);

    close(fd);
}

//**************************************************************************************/
// 7) Recover File 
//**************************************************************************************/
void file_recover(const char *disk, const char *fileName, int SHAflag){

   if( SHAflag==1 || multiFileChecker(disk,fileName)==-1){
    int fd = open(disk, O_RDWR); 
    int *boot_info = bootReader(disk,0);
    
    int sector_bytesNum = boot_info[0];
    int rs_num = boot_info[1];
    int fat_sec_num = boot_info[2];
    int cluster_size = boot_info[3];
    int fat_num = boot_info[4];
    int root_dir_cluster = boot_info[5];
    int fat_table_offset =boot_info[6];
    
    int data_region_offset = (rs_num+fat_num * fat_sec_num) * sector_bytesNum;
    int root_dir_offset = data_region_offset + (root_dir_cluster-2) * cluster_size * sector_bytesNum;
     unsigned char buffer[ENTRY_SIZE];
    int found =-1;
    int found2=-1;
   
    lseek(fd, root_dir_offset, SEEK_SET);

    while (read(fd, buffer, ENTRY_SIZE) == ENTRY_SIZE) {
       
        if (buffer[0] == 0xE5) { 
            char df_name[13] = {0};
            strncpy(df_name, (char *)buffer + 1, 8); 
            for (int i = 7; i >= 0; i--) {
                if (df_name[i] == ' ') {
                    df_name[i] = '\0'; 
                }
            }

            if (buffer[8] != ' ') {
                //has ext 
                char cup[5] = "."; 
                strncat(cup, (char *)buffer + 8, 3); 
                strcat(df_name, cup); 
            }

            if (strcmp(df_name, fileName + 1) == 0) {

                found = 1;
                
                if(SHAflag!=1){
                    buffer[0] = fileName[0]; 
                    lseek(fd, -ENTRY_SIZE, SEEK_CUR);
                    write(fd, buffer, ENTRY_SIZE);
                }  
                
                int start_cluster=0;
                 start_cluster+=buffer[26];
                 start_cluster+=buffer[27]*256;
                
                 int remaining_size = 0;
                   remaining_size += buffer[28];        
                     remaining_size += buffer[29] * 256; 
                     remaining_size += buffer[30] * 256 * 256; 
                      remaining_size += buffer[31] * 256 * 256 * 256; 

                int file_offset2 = data_region_offset+(start_cluster-2)*cluster_size*sector_bytesNum;
                int cur_cluster = start_cluster;
                off_t cur_pos= lseek(fd, 0, SEEK_CUR);
                int file_offset = 0;

                // READ FILE----------------------------------------------------
                if(SHAflag==1){

                    unsigned char buffer2[remaining_size + 1];           
                    lseek(fd, file_offset2, SEEK_SET);
                    read(fd, buffer2, remaining_size);   
                    buffer2[remaining_size] = '\0';

                    //7B-------------------------------
                     if(remaining_size > cluster_size * sector_bytesNum){
              
                        unsigned char *buffer3 = ClusterFinder(fd, start_cluster, remaining_size, data_region_offset, cluster_size, sector_bytesNum, fat_table_offset);
                         int c_flag=SHAcomparator((const char *)buffer3);
                        if(c_flag==1){
                            found2 =1;

                             buffer[0] = fileName[0]; 
                        lseek(fd,cur_pos,SEEK_SET);
                        lseek(fd, -ENTRY_SIZE, SEEK_CUR);
                        write(fd, buffer, ENTRY_SIZE);
                      
                             printf("%s: successfully recovered with SHA-1\n", fileName);
                         }

                     }else{
           
                    int c_flag=SHAcomparator((const char *)buffer2);
                    if(c_flag==1){
            
                        found2 =1;
                
                         buffer[0] = fileName[0]; 
                        lseek(fd,cur_pos,SEEK_SET);
                        lseek(fd, -ENTRY_SIZE, SEEK_CUR);
                        write(fd, buffer, ENTRY_SIZE);

                        printf("%s: successfully recovered with SHA-1\n", fileName);
                 
                    }else{
                        
                    }
                       lseek(fd,cur_pos,SEEK_SET);
              
                }    
            }                  
    
           if(SHAflag!=1){
           
                while (remaining_size > 0){
                    int fat_entry_offset = fat_table_offset + cur_cluster * 4;
                    int next_cluster=cur_cluster + 1;  

                    if (remaining_size <= cluster_size * sector_bytesNum) {
                        next_cluster = 0x0FFFFFF8; 
                    }
                 
                     FATupdate(fd, fat_entry_offset, next_cluster);     

                    cur_cluster = next_cluster;
                     file_offset+=cluster_size * sector_bytesNum;
                    remaining_size -= cluster_size * sector_bytesNum;
                    
                };
           }else if(SHAflag==1&&found2==1){
     
             while (remaining_size > 0){

                    int fat_entry_offset = fat_table_offset + cur_cluster * 4;
                    int next_cluster=cur_cluster + 1;  

                    if (remaining_size <= cluster_size * sector_bytesNum) {
                        next_cluster = 0x0FFFFFF8; 
                    }
                      //----------------------------------------------
                     FATupdate(fd, fat_entry_offset, next_cluster);     

                    cur_cluster = next_cluster;
                     file_offset+=cluster_size * sector_bytesNum;
                    remaining_size -= cluster_size * sector_bytesNum;
                    
                };

           }
                //---------------------------------------------------------------------------------------------------
            
              if(SHAflag!=1&&found==1){
                     printf("%s: successfully recovered\n", fileName);
                          exit(0);
                break;
                }
            }
        }else if(buffer[0]=='\0'||buffer[0]==' '){
            continue;
        }else{
           continue;
        }
       
    }

    if((SHAflag==1&&found2==-1)||found==-1){
         printf("%s: file not found\n", fileName);
              exit(0);
    }
    close(fd);
   }
}

//**************************************************************************************/
// 8) Main 
//**************************************************************************************/
int main(int argc, char *argv[]){
      
    opterr = 0; 
    int cmd;
    int val_flag=0;
    if(argc<3){
         printf("Usage: ./nyufile disk <options>\n");
            printf("  -i                     Print the file system information.\n");
            printf("  -l                     List the root directory.\n");
            printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
            printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
            exit(0);
    }
    while ((cmd = getopt(argc, argv, "ilr:R:s:")) !=-1) {
    switch (cmd) {
        case 'i':
            //Call the FS_Info
             int* uselessInfo = malloc(7 * sizeof(int));
            uselessInfo=bootReader(argv[1],1);
            free(uselessInfo);
        
           val_flag=1;
            break;
        case 'l':
            //Call the List 
            listRootDir(argv[1]);
          
           val_flag=1;
            break;
        case 'r':
            if(argc==6){
               
                      sha_para=argv[5];
               file_recover(argv[1],optarg,1);
         
             val_flag=1;
             break;
             }else if (argc==5){
                val_flag=0;
                break;
             }else{
             file_recover(argv[1], optarg,0);
             }
           
          val_flag=1;
            break;
        case 'R':
            if(argc!=6){ 
                val_flag=0;
                break;
            }
            printf("Recover a possibly non-contiguous file.\n");
            printf("Work in progress...\n");
            val_flag=1;
            break;
       
           
    }
    } 
        if(val_flag==0){
            printf("Usage: ./nyufile disk <options>\n");
            printf("  -i                     Print the file system information.\n");
            printf("  -l                     List the root directory.\n");
            printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
            printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
        }
   

return 0;
}