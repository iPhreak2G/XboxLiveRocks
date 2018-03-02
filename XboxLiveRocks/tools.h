#pragma once

#ifndef _KEYVAULT__H 
#define _KEYVAULT__H

#pragma pack(1)
typedef enum _ODD_POLICY {
    ODD_POLICY_FLAG_CHECK_FIRMWARE = 0x120, 
} ODD_POLICY;
typedef union _INQUIRY_DATA {
    struct {
        BYTE DeviceType          : 5;
        BYTE DeviceTypeQualifier : 3;
        BYTE DeviceTypeModifier  : 7;
        BYTE RemovableMedia      : 1;
        BYTE Versions            : 8;
        BYTE ResponseDataFormat  : 4;
        BYTE HiSupport           : 1;
        BYTE NormACA             : 1;
        BYTE ReservedBit         : 1;
        BYTE AERC                : 1;
        BYTE AdditionalLength    : 8;
        WORD Reserved            : 16;
        BYTE SoftReset           : 1;
        BYTE CommandQueue        : 1;
        BYTE Reserved2           : 1;
        BYTE LinkedCommands      : 1;
        BYTE Synchronous         : 1;
        BYTE Wide16Bit           : 1;
        BYTE Wide32Bit           : 1;
        BYTE RelativeAddressing  : 1;
        BYTE VendorId[8];
        BYTE ProductId[16];
        BYTE ProductRevisionLevel[4];
    };
    BYTE Data[0x24];
} INQUIRY_DATA, *pINQUIRY_DATA;
typedef struct _XEIKA_ODD_DATA {
    BYTE         Version;
    BYTE         PhaseLevel;
    INQUIRY_DATA InquiryData;
} XEIKA_ODD_DATA, *PXEIKA_ODD_DATA;
typedef struct _XEIKA_DATA {
    XECRYPT_RSAPUB_2048 PublicKey;
    DWORD               Signature;
    WORD                Version;
    XEIKA_ODD_DATA      OddData;
    BYTE                Padding[4];
} XEIKA_DATA, *PXEIKA_DATA;
typedef struct _XEIKA_CERTIFICATE {
    WORD       Size;
    XEIKA_DATA Data;
    BYTE       Padding[0x1146];
} XEIKA_CERTIFICATE, *PXEIKA_CERTIFICATE;
typedef struct _KEY_VAULT {                     // Key #
    BYTE  HmacShaDigest[0x10];
    BYTE  Confounder[0x08];
    BYTE  ManufacturingMode;                    // 0x00
    BYTE  AlternateKeyVault;                    // 0x01
    BYTE  RestrictedPrivilegesFlags;            // 0x02
    BYTE  ReservedByte3;                        // 0x03
    WORD  OddFeatures;                          // 0x04
    WORD  OddAuthtype;                          // 0x05
    DWORD RestrictedHvextLoader;                // 0x06
    DWORD PolicyFlashSize;                      // 0x07
    DWORD PolicyBuiltinUsbmuSize;               // 0x08
    DWORD ReservedDword4;                       // 0x09
    QWORD RestrictedPrivileges;                 // 0x0A
    QWORD ReservedQword2;                       // 0x0B
    QWORD ReservedQword3;                       // 0x0C
    QWORD ReservedQword4;                       // 0x0D
    BYTE  ReservedKey1[0x10];                   // 0x0E
    BYTE  ReservedKey2[0x10];                   // 0x0F
    BYTE  ReservedKey3[0x10];                   // 0x10
    BYTE  ReservedKey4[0x10];                   // 0x11
    BYTE  ReservedRandomKey1[0x10];             // 0x12
    BYTE  ReservedRandomKey2[0x10];             // 0x13
    BYTE  ConsoleSerialNumber[0xC];             // 0x14
    BYTE  MoboSerialNumber[0xC];                // 0x15
    WORD  GameRegion;                           // 0x16
    BYTE  Padding1[0x6];
    BYTE  ConsoleObfuscationKey[0x10];          // 0x17
    BYTE  KeyObfuscationKey[0x10];              // 0x18
    BYTE  RoamableObfuscationKey[0x10];         // 0x19
    BYTE  DvdKey[0x10];                         // 0x1A
    BYTE  PrimaryActivationKey[0x18];           // 0x1B
    BYTE  SecondaryActivationKey[0x10];         // 0x1C
    BYTE  GlobalDevice2desKey1[0x10];           // 0x1D
    BYTE  GlobalDevice2desKey2[0x10];           // 0x1E
    BYTE  WirelessControllerMs2desKey1[0x10];   // 0x1F
    BYTE  WirelessControllerMs2desKey2[0x10];   // 0x20
    BYTE  WiredWebcamMs2desKey1[0x10];          // 0x21
    BYTE  WiredWebcamMs2desKey2[0x10];          // 0x22
    BYTE  WiredControllerMs2desKey1[0x10];      // 0x23
    BYTE  WiredControllerMs2desKey2[0x10];      // 0x24
    BYTE  MemoryUnitMs2desKey1[0x10];           // 0x25
    BYTE  MemoryUnitMs2desKey2[0x10];           // 0x26
    BYTE  OtherXsm3DeviceMs2desKey1[0x10];      // 0x27
    BYTE  OtherXsm3DeviceMs2desKey2[0x10];      // 0x28
    BYTE  WirelessController3p2desKey1[0x10];   // 0x29
    BYTE  WirelessController3p2desKey2[0x10];   // 0x2A
    BYTE  WiredWebcam3p2desKey1[0x10];          // 0x2B
    BYTE  WiredWebcam3p2desKey2[0x10];          // 0x2C
    BYTE  WiredController3p2desKey1[0x10];      // 0x2D
    BYTE  WiredController3p2desKey2[0x10];      // 0x2E
    BYTE  MemoryUnit3p2desKey1[0x10];           // 0x2F
    BYTE  MemoryUnit3p2desKey2[0x10];           // 0x30
    BYTE  OtherXsm3Device3p2desKey1[0x10];      // 0x31
    BYTE  OtherXsm3Device3p2desKey2[0x10];      // 0x32
    XECRYPT_RSAPRV_1024 ConsolePrivateKey;      // 0x33
    XECRYPT_RSAPRV_2048 XeikaPrivateKey;        // 0x34
    XECRYPT_RSAPRV_1024 CardeaPrivateKey;       // 0x35
    XE_CONSOLE_CERTIFICATE ConsoleCertificate;  // 0x36
    XEIKA_CERTIFICATE XeikaCertificate;         // 0x37
    BYTE  KeyVaultSignature[0x100];             // 0x44
    BYTE  CardeaCertificate[0x2108];            // 0x38
} KEY_VAULT, *PKEY_VAULT;

#pragma pack()
extern BYTE kvDigest[XECRYPT_SHA_DIGEST_SIZE];
extern BYTE cpuKey[0x10];

extern BOOL  fcrt;
extern BOOL  crl;
extern BOOL  type1KV;

BOOL VerifyKeyVault();
HRESULT SetKeyVault(BYTE* KeyVault);
HRESULT ProcessKeyVault();
HRESULT SetKeyVault(CHAR* FilePath);
HRESULT LoadKeyVault(CHAR* FilePath);
#endif
namespace Tools 
{
	BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa);
	DWORD applyPatchData(PVOID buffer);
	typedef HRESULT(*pDmSetMemory)(LPVOID lpbAddr, DWORD cb, LPCVOID lpbBuf, LPDWORD pcbRet);

	class MemoryBuffer
	{
	public:
		MemoryBuffer(DWORD dwSize = 512)
		{
			m_pBuffer = NULL;
			m_dwDataLength = 0;
			m_dwBufferSize = 0;

			if ((dwSize < UINT_MAX) && (dwSize != 0))
			{
				m_pBuffer = (BYTE*)malloc(dwSize + 1);

				if (m_pBuffer)
				{
					m_dwBufferSize = dwSize;
					m_pBuffer[0] = 0;
				}
			}
		};

		~MemoryBuffer() 
		{
			if (m_pBuffer) free(m_pBuffer);

			m_pBuffer = NULL;
			m_dwDataLength = 0;
			m_dwBufferSize = 0;
		};

		bool Add(CONST PVOID p, DWORD dwSize)
		{
			if (CheckSize(dwSize)) 
			{
				memcpy(m_pBuffer + m_dwDataLength, p, dwSize);
				m_dwDataLength += dwSize;
				*(m_pBuffer + m_dwDataLength) = 0;
				return true;
			}
			else
				return false;
		};

		PBYTE GetData() CONST { return m_pBuffer; };
		DWORD GetDataLength() CONST { return m_dwDataLength; };
		void Rewind() { m_dwDataLength = 0; m_pBuffer[0] = 0; };

		bool CheckSize(DWORD dwSize) 
		{
			if (m_dwBufferSize >= (m_dwDataLength + dwSize))
				return true;
			else
			{
				DWORD dwNewSize = max(m_dwDataLength + dwSize, m_dwBufferSize * 2);
				BYTE* pNewBuffer = (PUCHAR)realloc(m_pBuffer, dwNewSize + 1);
				if (pNewBuffer)
				{
					m_pBuffer = pNewBuffer;
					m_dwBufferSize = dwNewSize;
					return true;
				}
				else  return false;
			}
		}

	private:
		PBYTE m_pBuffer;
		DWORD m_dwDataLength;
		DWORD m_dwBufferSize;
	};

	void ThreadMe(LPTHREAD_START_ROUTINE lpStartAddress);

	void XNotifyUI(char* Type, PWCHAR pwszStringParam);

	DWORD CreateSymbolicLink(char* szDrive, char* szDeviceName, bool System);

	BOOL XeKeysPkcs1Verify(const BYTE* pbHash, const BYTE* pbSig, XECRYPT_RSA* pRsa);

	DWORD ApplyPatches(void* buffer);
	void HookFunctionStart(DWORD* Address, DWORD* SaveStub, DWORD Destination);
	void PatchInJump(DWORD* Address, DWORD Destination, bool Linked = false);
	FARPROC ResolveFunction(char* ModuleName, DWORD Ordinal);
	DWORD PatchModuleImport(char* Module, char* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
	DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, char* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);

	bool CReadFile(const char* FileName, MemoryBuffer &pBuffer);
	bool CWriteFile(const char* FilePath, const void* Data, DWORD Size);
	bool FileExists(LPCSTR lpFileName);
}