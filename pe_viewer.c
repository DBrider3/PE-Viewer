#include <stdio.h>
#include <Windows.h> // sleep
#include <stdlib.h> // exit()
#include <string.h>

#define ULONGLONG 8
#define DWORD 4
#define BYTE 1 
#define WORD 2
#define uchar unsigned char
#define Little_endian 0
#define Big_endian 1

void print_ascii(char * ptr, int size) { // ascii print
	printf("( ");
	for (int i = 0; i < size; i++) {
		printf("%c", ptr[i]);
	}
	printf(" )");
	
}
void print_hex(uchar * ptr, int size, int reverse) { // hex print, reverse: default 0
	if (reverse) { // big endian
		for (int i = size -1; i >= 0; i--) {
			printf("%02X", ptr[i]);
		}
	}
	else { // little endian 
		for (int i = 0; i < size; i++) {
			printf("%02X ", ptr[i]);
			if (i != 0 && (i+1) % 16 == 0) {
				printf("\n");
			}
			else if (i != 0 && (i+1) % 8 == 0) {
				printf("| ");
			}
		}
	}
	
}

int main(void) {

	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS32 nt_header;
	IMAGE_SECTION_HEADER section_header;

	FILE *fileIn;
	char *filename;
	int numberOfSections = 0;
	uchar e_magic[WORD];

	while (1) {
		int select;
		printf("할일을 선택해 주세요\n1.pe분석 2.종료 : ");
		scanf("%d", &select);
		getchar();
		if (select == 1) {

			// 동적으로 파일이름 최대길이 만큼 할당하고 입력받기 (대략적으로 함, 자유롭게 하세요)
			filename = malloc(sizeof(char) * 256);
			printf("파일 이름을 입력하세요 : ");
			scanf("%s", filename);


			// 입력받은 이진파일을 읽기 전용으로 열기
			if ((fileIn = fopen(filename, "rb")) == NULL) {
				fputs("File Open Error!\n", stderr);
				continue;
			}
			// DOS HEADER
			printf("\n<DOS Header>\n");
			//printf("\taddress : %08X\n", ftell(fileIn)); // -> 0 출력

			fread((void*)(&dos_header), sizeof(dos_header), 1, fileIn);

			if (strncmp(&dos_header.e_magic, "MZ", 2) != 0) // PE check
				printf("This is not PE file");

			print_hex(&dos_header, sizeof(dos_header), 0);

			printf("%08X ", (&dos_header.e_magic - &dos_header));
			printf("e_magic : ");
			print_hex(&dos_header.e_magic, WORD, Little_endian);
			print_ascii(&dos_header.e_magic, sizeof(dos_header.e_magic));
			printf("\n");


			printf("%08X ", ((char *)&dos_header.e_lfanew- &dos_header));
			printf("e_lfanew : ");
			print_hex(&dos_header.e_lfanew, WORD, Little_endian);
			printf("\n");



			// NT HEADERS
			printf("\n<NT Header>\n");

			fseek(fileIn, dos_header.e_lfanew, SEEK_SET);
			//printf("\taddress : %08X\n", ftell(fileIn));
			char* nt_header_addr = ftell(fileIn);

			fread((void*)(&nt_header), sizeof(nt_header), 1, fileIn);

			if (strncmp(&nt_header.Signature, "PE", 2) != 0) // PE check
				printf("This is not PE file");

			printf("%08X ", ((char *)&nt_header.Signature - &nt_header) + nt_header_addr);
			printf("Signature : ");
			print_ascii(&nt_header.Signature, sizeof(nt_header.Signature));
			printf("\n");

			printf("%08X ", ((char *)&nt_header.FileHeader.Machine - &nt_header) + nt_header_addr);
			printf("Machine : ");
			print_hex(&nt_header.FileHeader.Machine, WORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.FileHeader.NumberOfSections - &nt_header) + nt_header_addr);
			printf("NumberOfSections : ");
			print_hex(&nt_header.FileHeader.NumberOfSections, WORD, Big_endian);
			numberOfSections = nt_header.FileHeader.NumberOfSections; // section 개수 check
			printf("\n");

			printf("%08X ", ((char *)&nt_header.FileHeader.SizeOfOptionalHeader - &nt_header) + nt_header_addr);
			printf("SizeOfOptionalHeader : ");
			print_hex(&nt_header.FileHeader.SizeOfOptionalHeader, WORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.FileHeader.Characteristics - &nt_header) + nt_header_addr);
			printf("Characteristics : ");
			print_hex(&nt_header.FileHeader.Characteristics, WORD, Big_endian);
			printf("\n");
			if (nt_header.FileHeader.Characteristics & 0x2) printf("\tIMAGE_FILE_EXECUTABLE_IMAGE\n\n");
			if (nt_header.FileHeader.Characteristics & 0x2000) printf("\t\tIMAGE_FILE_DLL\n\n");
			
			// IMAGE_OPTIONAL_HEADER32
			printf("\n<NT Header - Optional Header>\n");
			printf("%08X ", ((char *)&nt_header.OptionalHeader.Magic - &nt_header) + nt_header_addr);
			printf("Magic : ");
			print_hex(&nt_header.OptionalHeader.Magic, WORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.AddressOfEntryPoint - &nt_header) + nt_header_addr);
			printf("AddressOfEntryPoint : ");
			print_hex(&nt_header.OptionalHeader.AddressOfEntryPoint, DWORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.ImageBase - &nt_header) + nt_header_addr);
			printf("ImageBase : ");
			print_hex(&nt_header.OptionalHeader.ImageBase, DWORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.SectionAlignment - &nt_header) + nt_header_addr);
			printf("SectionAlignment : ");
			print_hex(&nt_header.OptionalHeader.SectionAlignment, DWORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.FileAlignment - &nt_header) + nt_header_addr);
			printf("FileAlignment : ");
			print_hex(&nt_header.OptionalHeader.FileAlignment, DWORD, Big_endian);
			printf("\n");
			
			printf("%08X ", ((char *)&nt_header.OptionalHeader.SizeOfImage - &nt_header) + nt_header_addr);
			printf("SizeOfImage : ");
			print_hex(&nt_header.OptionalHeader.SizeOfImage, DWORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.SizeOfHeaders - &nt_header) + nt_header_addr);
			printf("SizeOfHeaders : ");
			print_hex(&nt_header.OptionalHeader.SizeOfHeaders, DWORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.Subsystem - &nt_header) + nt_header_addr);
			printf("Subsystem : ");
			print_hex(&nt_header.OptionalHeader.Subsystem, WORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.NumberOfRvaAndSizes - &nt_header) + nt_header_addr);
			printf("NumberOfRvaAndSizes : ");
			print_hex(&nt_header.OptionalHeader.NumberOfRvaAndSizes, DWORD, Big_endian);
			printf("\n");

			printf("%08X ", ((char *)&nt_header.OptionalHeader.DataDirectory - &nt_header) + nt_header_addr);
			printf("DataDirectory : \n");
			for (int i = 0; i < 17; i++)
			{
				if (i == 0 || i == 1 || i == 2 || i == 9) {
					if (i == 0) {
						printf("\tEXPORT Table(RVA, size) : ");
					}
					else if (i == 1) {
						printf("\tIMPORT Table(RVA, size) : ");
					}
					else if (i == 2) {
						printf("\tRESOURCE Table(RVA, size) : ");
					}
					else if (i == 9) {
						printf("\tTLS Table(RVA, size) : ");
					}
					print_hex(&nt_header.OptionalHeader.DataDirectory[i], sizeof(nt_header.OptionalHeader.DataDirectory[i]) / 2, 1);
					printf(" | ");
					print_hex((char *)(&nt_header.OptionalHeader.DataDirectory[i]) + 4, sizeof(nt_header.OptionalHeader.DataDirectory[i]) / 2, 1);
					printf("\n\n");
				}
				
			};
			// SECTION HEADER
			printf("\n<Section Header>\n");
			
			for (int i = 0; i < numberOfSections; i++)
			{
				char* section_header_addr = ftell(fileIn);
				fread((void *)(&section_header), sizeof(section_header), 1, fileIn);

				printf("%08X ", ((char *)&section_header.Name - &section_header) + section_header_addr);
				printf("section header Name : ");
				print_ascii(&section_header.Name, sizeof(section_header.Name));
				printf("\n");

				printf("%08X ", ((char *)&section_header.Misc.VirtualSize - &section_header) + section_header_addr);
				printf("section header VirtualSize : ");
				print_hex(&section_header.Misc.VirtualSize, DWORD, Big_endian);
				printf("\n");

				printf("%08X ", ((char *)&section_header.VirtualAddress - &section_header) + section_header_addr);
				printf("section header VirtualAddress(RVA) : ");
				print_hex(&section_header.VirtualAddress, DWORD, Big_endian);
				printf("\n");

				printf("%08X ", ((char *)&section_header.SizeOfRawData - &section_header) + section_header_addr);
				printf("section header SizeOfRawData : ");
				print_hex(&section_header.SizeOfRawData, DWORD, Big_endian);
				printf("\n");

				printf("%08X ", ((char *)&section_header.PointerToRawData - &section_header) + section_header_addr);
				printf("section header PointerToRawData : ");
				print_hex(&section_header.PointerToRawData, DWORD, Big_endian);
				printf("\n");

				printf("%08X ", ((char *)&section_header.Characteristics - &section_header) + section_header_addr);
				printf("section header Characteristics : ");
				print_hex(&section_header.Characteristics, DWORD, Big_endian);
				printf("\n\n");
			}
		
			printf("\n");
			free(filename); // 동적 메모리 해제 
			fclose(fileIn); // 파일 닫기
		}
		else if (select == 2) {
			printf("프로그램을 종료합니다.\n");
			Sleep(400); // 0.4 second delay
			break;
		}
		else {
			printf("잘못 입력하셨습니다.\n");
			continue;
		}
	}
	return 0;
}