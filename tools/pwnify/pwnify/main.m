//
//  main.m
//  pwnify
//
//  Created by Linus Henze.
//  Copyright © 2021 Linus Henze. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>

char *readFile(const char *path, size_t *size) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    void *fileBuf = malloc(*size);
    fread(fileBuf, 1, *size, f);
    fclose(f);
    
    return fileBuf;
}

BOOL writeFile(const char *path, const char *buf, size_t size) {
    FILE *f = fopen(path, "w+");
    if (f == NULL) {
        return NO;
    }
    
    fwrite(buf, 1, size, f);
    fclose(f);
    
    return YES;
}

int main(int argc, const char * argv[]) {
    if (argc != 3) {
        puts("Usage: pwnify <program to modify> <program to inject>");
        return -1;
    }
    
    // First read and modify pwn file
    size_t fileSize = 0;
    char *buf = readFile(argv[2], &fileSize);
    if (!buf) {
        printf("Failed to read %s!\n", argv[2]);
        return -1;
    }
    
    struct mach_header_64 *header = (struct mach_header_64*) buf;
    if (fileSize < sizeof(struct mach_header_64) || header->magic != MH_MAGIC_64) {
        printf("%s: Not a 64-bit MachO file!\n", argv[2]);
        return -1;
    }
    
    cpu_subtype_t subType = header->cpusubtype;
    
    header->cpusubtype = 0xDEADBEEF; // Temporarily change subtype
    
    if (writeFile("/tmp/pwnfile", buf, fileSize) == NO) {
        puts("Failed to write temporary pwn file!");
        return -1;
    }
    
    free(buf);
    
    // Then inject it
    if (system([[NSString stringWithFormat: @"/usr/bin/lipo -create -output %s %s %s", "/tmp/pwn-output", argv[1], "/tmp/pwnfile"] UTF8String]) != 0) {
        puts("Failed to build universal binary!");
        return -1;
    }
    
    // And modify the result again
    buf = readFile("/tmp/pwn-output", &fileSize);
    if (!buf) {
        puts("Failed to read lipo output file!");
        return -1;
    }
    
    struct fat_header *fatHeader = (struct fat_header*) buf;
    if (OSSwapBigToHostInt32(fatHeader->magic) != FAT_MAGIC) {
        puts("Lipo created a non-fat file?!");
        return -1;
    }
    
    struct fat_arch *arch = (struct fat_arch*) ((uintptr_t) fatHeader + sizeof(fatHeader));
    for (size_t i = 0; i < OSSwapBigToHostInt32(fatHeader->nfat_arch); i++) {
        if (OSSwapBigToHostInt32(arch[i].cpusubtype) == 0xDEADBEEF) {
            uint32_t offset = OSSwapBigToHostInt32(arch[i].offset);
            struct mach_header_64 *header = (struct mach_header_64*) ((uintptr_t) fatHeader + offset);
            
            arch[i].cpusubtype = OSSwapHostToBigInt32(subType);
            header->cpusubtype = subType;
        } else {
            arch[i].cpusubtype = OSSwapHostToBigInt32(2);
        }
    }
    
    if (writeFile(argv[1], buf, fileSize) == NO) {
        puts("Failed to write final pwn file!");
        return -1;
    }
    
    free(buf);
    
    return 0;
}
