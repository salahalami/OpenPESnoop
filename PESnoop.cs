/*
 * Created by SharpDevelop.
 * Date: 9/25/2015
 * Time: 6:22 AM
 * 
 * Copyright (C) 2015 Salah Alami. All Rights Reserved.
 * Contact: salahalami21@gmail.com
 * City: Casablanca, Morocco
 * 
 */
using System;
using System.IO;
using System.Text;

namespace OpenPESnoop
{
	/// <summary>
	/// PESnoop is a class for reading data structures residing inside
	/// a PE file.
	/// </summary>
	public class PESnoop
	{
		ushort DH_e_magic;
		ushort DH_e_cblp;
		ushort DH_e_cp;
		ushort DH_e_crlc;
		ushort DH_e_cparhdr;
		ushort DH_e_minalloc;
		ushort DH_e_maxalloc;
		ushort DH_e_ss;
		ushort DH_e_sp;
		ushort DH_e_csum;
		ushort DH_e_ip;
		ushort DH_e_cs;
		ushort DH_e_lfarlc;
		ushort DH_e_ovno;
		ushort[] DH_e_res;//4
		ushort DH_e_oemid;
		ushort DH_e_oeminfo;
		ushort[] DH_e_res2;//10
		uint DH_e_lfanew;
		
		uint NH_Signature;
		
		ushort FH_Machine;
		ushort FH_NumberOfSections;
		uint FH_TimeDateStamp;
		uint FH_PointerToSymbolTable;
		uint FH_NumberOfSymbols;
		ushort FH_SizeOfOptionalHeader;
		ushort FH_Characteristics;
		
		ushort OH_Magic;
		byte OH_MajorLinkerVersion;
		byte OH_MinorLinkerVersion;
		uint OH_SizeOfCode;
		uint OH_SizeOfInitializedData;
		uint OH_SizeOfUninitializedData;
		uint OH_AddressOfEntryPoint;
		uint OH_BaseOfCode;
		uint OH_BaseOfData;
		ulong OH_ImageBase;
		uint OH_SectionAlignment;
		uint OH_FileAlignment;
		ushort OH_MajorOperatingSystemVersion;
		ushort OH_MinorOperatingSystemVersion;
		ushort OH_MajorImageVersion;
		ushort OH_MinorImageVersion;
		ushort OH_MajorSubsystemVersion;
		ushort OH_MinorSubsystemVersion;
		uint OH_Win32VersionValue;
		uint OH_SizeOfImage;
		uint OH_SizeOfHeaders;
		uint OH_CheckSum;
		ushort OH_Subsystem;
		ushort OH_DllCharacteristics;
		ulong OH_SizeOfStackReserve;
		ulong OH_SizeOfStackCommit;
		ulong OH_SizeOfHeapReserve;
		ulong OH_SizeOfHeapCommit;
		uint OH_LoaderFlags;
		uint OH_NumberOfRvaAndSizes;
		
		uint[] OH_DD_VirtualAddress;
		uint[] OH_DD_Size;
		
		byte[][] SH_Name;
		uint[] SH_Misc;
		uint[] SH_VirtualAddress;
		uint[] SH_SizeOfRawData;
		uint[] SH_PointerToRawData;
		uint[] SH_PointerToRelocations;
		uint[] SH_PointerToLinenumbers;
		ushort[] SH_NumberOfRelocations;
		ushort[] SH_NumberOfLinenumbers;
		uint[] SH_Characteristics;
		
		uint ED_Characteristics;
		uint ED_TimeDateStamp;
		ushort ED_MajorVersion;
		ushort ED_MinorVersion;
		uint ED_Name;
		uint ED_Base;
		uint ED_NumberOfFunctions;
		uint ED_NumberOfNames;
		uint ED_AddressOfFunctions;
		uint ED_AddressOfNames;
		uint ED_AddressOfNameOrdinals;
		
		string ED_NameValue;
		uint[] ED_AddressOfFunctionsValues;
		uint[] ED_AddressOfNamesValues;
		ushort[] ED_AddressOfNameOrdinalsValues;
		string[] ED_FunctionNamesValues;
		
		public PESnoop()
		{
			
		}
		
		public PESnoop(string fileName)
		{
			GetDosHeader(fileName);
			GetNtHeaders(fileName);
			GetSectionHeader(fileName);
			GetExportDirectory(fileName);
		}
		
		ushort ReadWord(FileStream fs)
		{
			byte[] b = new byte[2];
			fs.Read(b, 0, 2);
			return (ushort)((((ushort)b[1]) << 8) | ((ushort)b[0]));
		}
		
		uint ReadDword(FileStream fs)
		{
			ushort[] u = new ushort[2];
			u[0] = ReadWord(fs);
			u[1] = ReadWord(fs);
			return (uint)((((uint)u[1]) << 16) | ((uint)u[0]));
		}
		
		ulong ReadQword(FileStream fs)
		{
			uint[] u = new uint[2];
			u[0] = ReadDword(fs);
			u[1] = ReadDword(fs);
			return (ulong)((((ulong)u[1]) << 32) | ((ulong)u[0]));
		}
		
		void GetDosHeader(string fileName)
		{
			using(FileStream fs = new FileStream(fileName, FileMode.Open))
			{
				DH_e_magic = ReadWord(fs);
				DH_e_cblp = ReadWord(fs);
				DH_e_cp = ReadWord(fs);
				DH_e_crlc = ReadWord(fs);
				DH_e_cparhdr = ReadWord(fs);
				DH_e_minalloc = ReadWord(fs);
				DH_e_maxalloc = ReadWord(fs);
				DH_e_ss = ReadWord(fs);
				DH_e_sp = ReadWord(fs);
				DH_e_csum = ReadWord(fs);
				DH_e_ip = ReadWord(fs);
				DH_e_cs = ReadWord(fs);
				DH_e_lfarlc = ReadWord(fs);
				DH_e_ovno = ReadWord(fs);
				ushort[] tmp = new ushort[4];
				for (int i = 0; i < 4; i++) 
					tmp[i] = ReadWord(fs);
				DH_e_res = tmp;
				DH_e_oemid = ReadWord(fs);
				DH_e_oeminfo = ReadWord(fs);
				tmp = new ushort[10];
				for (int i = 0; i < 10; i++) 
				{
					tmp[i] = ReadWord(fs);
				}
				DH_e_res2 = tmp;
				DH_e_lfanew = ReadDword(fs);
			}
		}
		
		public void SetDosHeader(
			ushort e_magic, ushort e_cblp, ushort e_cp,
			ushort e_crlc, ushort e_cparhdr, ushort e_minalloc,
			ushort e_maxalloc, ushort e_ss, ushort e_sp,
			ushort e_csum, ushort e_ip, ushort e_cs,
			ushort e_lfarlc, ushort e_ovno, ushort[] e_res,
			ushort e_oemid, ushort e_oeminfo, ushort[] e_res2,
			uint e_lfanew
		)
		{
			DH_e_magic = e_magic;
			DH_e_cblp = e_cblp;
			DH_e_cp = e_cp;
			DH_e_crlc = e_crlc;
			DH_e_cparhdr = e_cparhdr;
			DH_e_minalloc = e_minalloc;
			DH_e_maxalloc = e_maxalloc;
			DH_e_ss = e_ss;
			DH_e_sp = e_sp;
			DH_e_csum = e_csum;
			DH_e_ip = e_ip;
			DH_e_cs = e_cs;
			DH_e_lfarlc = e_lfarlc;
			DH_e_ovno = e_ovno;
			DH_e_res = e_res;
			DH_e_oemid = e_oemid;
			DH_e_oeminfo = e_oeminfo;
			DH_e_res2 = e_res2;
			DH_e_lfanew = e_lfanew;
		}
		
		public void PrintDosHeader()
		{
			const string format =
				"->DOS Header\n"+
				"   e_magic:     0x{0}\n"+
				"   e_cblp:      0x{1}\n"+
				"   e_cp:        0x{2}\n"+
				"   e_crlc:      0x{3}\n"+
				"   e_cparhdr:   0x{4}\n"+
				"   e_minalloc:  0x{5}\n"+
				"   e_maxalloc:  0x{6}\n"+
				"   e_ss:        0x{7}\n"+
				"   e_sp:        0x{8}\n"+
				"   e_csum:      0x{9}\n"+
				"   e_ip:        0x{10}\n"+
				"   e_cs:        0x{11}\n"+
				"   e_lfarlc:    0x{12}\n"+
				"   e_ovno:      0x{13}\n"+
				"   e_res:       0x{14}{15}{16}{17}\n"+
				"   e_oemid:     0x{18}\n"+
				"   e_oeminfo:   0x{19}\n"+
				"   e_res2:      0x{20}{21}{22}{23}{24}{25}{26}{27}{28}"+
					"{29}\n"+
				"   e_lfanew:    0x{30}\n"
			;
			
			string buf = string.Format(
				format,
				DH_e_magic.ToString("X4"),
				DH_e_cblp.ToString("X4"),
				DH_e_cp.ToString("X4"),
				DH_e_crlc.ToString("X4"),
				DH_e_cparhdr.ToString("X4"),
				DH_e_minalloc.ToString("X4"),
				DH_e_maxalloc.ToString("X4"),
				DH_e_ss.ToString("X4"),
				DH_e_sp.ToString("X4"),
				DH_e_csum.ToString("X4"),
				DH_e_ip.ToString("X4"),
				DH_e_cs.ToString("X4"),
				DH_e_lfarlc.ToString("X4"),
				DH_e_ovno.ToString("X4"),
				DH_e_res[0].ToString("X4"),
				DH_e_res[1].ToString("X4"),
				DH_e_res[2].ToString("X4"),
				DH_e_res[3].ToString("X4"),
				DH_e_oemid.ToString("X4"),
				DH_e_oeminfo.ToString("X4"),
				DH_e_res2[0].ToString("X4"),
				DH_e_res2[1].ToString("X4"),
				DH_e_res2[2].ToString("X4"),
				DH_e_res2[3].ToString("X4"),
				DH_e_res2[4].ToString("X4"),
				DH_e_res2[5].ToString("X4"),
				DH_e_res2[6].ToString("X4"),
				DH_e_res2[7].ToString("X4"),
				DH_e_res2[8].ToString("X4"),
				DH_e_res2[9].ToString("X4"),
				DH_e_lfanew.ToString("X8")
			);
			
			Console.WriteLine(buf);
		}
		
		void GetNtHeaders(string fileName)
		{
			using (FileStream fs = new FileStream(fileName, FileMode.Open)) 
			{
				fs.Position += DH_e_lfanew;
				NH_Signature = ReadDword(fs);
				
				FH_Machine = ReadWord(fs);
				FH_NumberOfSections = ReadWord(fs);
				FH_TimeDateStamp = ReadDword(fs);
				FH_PointerToSymbolTable = ReadDword(fs);
				FH_NumberOfSymbols = ReadDword(fs);
				FH_SizeOfOptionalHeader = ReadWord(fs);
				FH_Characteristics = ReadWord(fs);
				
				bool OH32 = (FH_SizeOfOptionalHeader == 224);
				
				OH_Magic = ReadWord(fs);
				OH_MajorLinkerVersion = (byte)fs.ReadByte();
				OH_MinorLinkerVersion = (byte)fs.ReadByte();
				OH_SizeOfCode = ReadDword(fs);
				OH_SizeOfInitializedData = ReadDword(fs);
				OH_SizeOfUninitializedData = ReadDword(fs);
				OH_AddressOfEntryPoint = ReadDword(fs);
				OH_BaseOfCode = ReadDword(fs);
				if (OH32)
				{
					OH_BaseOfData = ReadDword(fs);
					OH_ImageBase = ReadDword(fs);
				}
				else
					OH_ImageBase = ReadQword(fs);
				OH_SectionAlignment = ReadDword(fs);
				OH_FileAlignment = ReadDword(fs);
				OH_MajorOperatingSystemVersion = ReadWord(fs);
				OH_MinorOperatingSystemVersion = ReadWord(fs);
				OH_MajorImageVersion = ReadWord(fs);
				OH_MinorImageVersion = ReadWord(fs);
				OH_MajorSubsystemVersion = ReadWord(fs);
				OH_MinorSubsystemVersion = ReadWord(fs);
				OH_Win32VersionValue = ReadDword(fs);
				OH_SizeOfImage = ReadDword(fs);
				OH_SizeOfHeaders = ReadDword(fs);
				OH_CheckSum = ReadDword(fs);
				OH_Subsystem = ReadWord(fs);
				OH_DllCharacteristics = ReadWord(fs);
				if (OH32) 
				{
					OH_SizeOfStackReserve = ReadDword(fs);
					OH_SizeOfStackCommit = ReadDword(fs);
					OH_SizeOfHeapReserve = ReadDword(fs);
					OH_SizeOfHeapCommit = ReadDword(fs);
				}
				else
				{
					OH_SizeOfStackReserve = ReadQword(fs);
					OH_SizeOfStackCommit = ReadQword(fs);
					OH_SizeOfHeapReserve = ReadQword(fs);
					OH_SizeOfHeapCommit = ReadQword(fs);
				}
				OH_LoaderFlags = ReadDword(fs);
				OH_NumberOfRvaAndSizes = ReadDword(fs);
				OH_DD_VirtualAddress = new uint[16];
				OH_DD_Size = new uint[16];
				for (int i = 0; i < 16; i++) 
				{
					OH_DD_VirtualAddress[i] = ReadDword(fs);
					OH_DD_Size[i] = ReadDword(fs);
				}				
			}
		}
		
		public void SetNtHeaders(
			uint Signature, ushort fhMachine, ushort fhNumberOfSections,
			uint fhTimeDateStamp, uint fhPointerToSymbolTable,
			uint fhNumberOfSymbols, ushort fhSizeOfOptionalHeader,
			ushort fhCharacteristics, ushort ohMagic, 
			byte ohMajorLinkerVersion, byte ohMinorLinkerVersion,
			uint ohSizeOfCode, uint ohSizeOfInitializedData,
			uint ohSizeOfUninitializedData, uint ohAddressOfEntryPoint,
			uint ohBaseOfCode, uint ohBaseOfData, ulong ohImageBase,
			uint ohSectionAlignment, uint ohFileAlignment, 
			ushort ohMajorOperatingSystemVersion, 
			ushort ohMinorOperatingSystemVersion,
			ushort ohMajorImageVersion, ushort ohMinorImageVersion,
			ushort ohMajorSubsystemVersion, ushort ohMinorSubsystemVersion,
			uint ohWin32VersionValue, uint ohSizeOfImage, 
			uint ohSizeOfHeaders, uint ohCheckSum, ushort ohSubsystem,
			ushort ohDllCharacteristics, ulong ohSizeOfStackReserve,
			ulong ohSizeOfStackCommit, ulong ohSizeOfHeapReserve,
			ulong ohSizeOfHeapCommit, uint ohLoaderFlags,
			uint ohNumberOfRvaAndSizes, uint[] ohddVirtualAddress,
			uint[] ohddSize
		)
		{
			NH_Signature = Signature;
			FH_Machine = fhMachine;
			FH_NumberOfSections = fhNumberOfSections;
			FH_TimeDateStamp = fhTimeDateStamp;
			FH_PointerToSymbolTable = fhPointerToSymbolTable;
			FH_NumberOfSymbols = fhNumberOfSymbols;
			FH_SizeOfOptionalHeader = fhSizeOfOptionalHeader;
			FH_Characteristics = fhCharacteristics;
			bool OH32 = (fhSizeOfOptionalHeader == 224);
			OH_Magic = ohMagic;
			OH_MajorLinkerVersion = ohMajorLinkerVersion;
			OH_MinorLinkerVersion = ohMinorLinkerVersion;
			OH_SizeOfCode = ohSizeOfCode;
			OH_SizeOfInitializedData = ohSizeOfInitializedData;
			OH_SizeOfUninitializedData = ohSizeOfUninitializedData;
			OH_AddressOfEntryPoint = ohAddressOfEntryPoint;
			OH_BaseOfCode = ohBaseOfCode;
			if (OH32) 
				OH_BaseOfData = ohBaseOfData;
			OH_ImageBase = ohImageBase;
			OH_SectionAlignment = ohSectionAlignment;
			OH_FileAlignment = ohFileAlignment;
			OH_MajorOperatingSystemVersion = ohMajorOperatingSystemVersion;
			OH_MinorOperatingSystemVersion = ohMinorOperatingSystemVersion;
			OH_MajorImageVersion = ohMajorImageVersion;
			OH_MinorImageVersion = ohMinorImageVersion;
			OH_MajorSubsystemVersion = ohMajorSubsystemVersion;
			OH_MinorSubsystemVersion = ohMinorSubsystemVersion;
			OH_Win32VersionValue = ohWin32VersionValue;
			OH_SizeOfImage = ohSizeOfImage;
			OH_SizeOfHeaders = ohSizeOfHeaders;
			OH_CheckSum = ohCheckSum;
			OH_Subsystem = ohSubsystem;
			OH_DllCharacteristics = ohDllCharacteristics;
			OH_SizeOfStackReserve = ohSizeOfStackReserve;
			OH_SizeOfStackCommit = ohSizeOfStackCommit;
			OH_SizeOfHeapReserve = ohSizeOfHeapReserve;
			OH_SizeOfHeapCommit = ohSizeOfHeapCommit;
			OH_LoaderFlags = ohLoaderFlags;
			OH_NumberOfRvaAndSizes = ohNumberOfRvaAndSizes;
			OH_DD_VirtualAddress = ohddVirtualAddress;
			OH_DD_Size = ohddSize;
		}
		
		string MachineHint(ushort Machine)
		{
			switch (Machine) 
			{
					case 0x014c: return "I386";
					case 0x0162: return "R3000";
					case 0x0166: return "R4000";
					case 0x0168: return "R10000";
					case 0x0169: return "WCEMIPSV2";
					case 0x0184: return "ALPHA";
					case 0x01a2: return "SH3";
					case 0x01a3: return "SH3DSP";
					case 0x01a4: return "SH3E";
					case 0x01a6: return "SH4";
					case 0x01a8: return "SH5";
					case 0x01c0: return "ARM";
					case 0x01c2: return "THUMB";
					case 0x01d3: return "AM33";
					case 0x01F0: return "POWERPC";
					case 0x01f1: return "POWERPCFP";
					case 0x0200: return "IA64";
					case 0x0266: return "MIPS16";
					case 0x0284: return "ALPHA64/AXP64";
					case 0x0366: return "MIPSFPU";
					case 0x0466: return "MIPSFPU16";
					case 0x0520: return "TRICORE";
					case 0x0CEF: return "CEF";
					case 0x0EBC: return "EBC";
					case 0x8664: return "AMD64";
					case 0x9041: return "M32R";
					case 0xC0EE: return "CEE";
					default:return "UNKNOWN";
			}
		}
		
		string TimeDateStampHint(uint TimeDateStamp)
		{
			DateTime dt = new DateTime(1970, 1, 1, 0, 0, 0);
			dt = dt.AddSeconds(TimeDateStamp);
			return dt.ToString("ddd MMM dd hh:mm:ss yyyy");
		}
		
		bool AND(uint u1, uint u2)
		{
			return ((u1 & u2) != 0);
		}
		
		string FHCharacteristicsHint(ushort Characteristics)
		{
			string buf = default(string);
			string format = "                          ({0})\n";
			
			if (AND(Characteristics, 0x0001))
				buf += string.Format(format, "RELOCS_STRIPPED");
			if (AND(Characteristics, 0x0002))
				buf += string.Format(format, "EXECUTABLE_IMAGE");
			if (AND(Characteristics, 0x0004))
				buf += string.Format(format, "LINE_NUMS_STRIPPED");
			if (AND(Characteristics, 0x0008))
				buf += string.Format(format, "LOCAL_SYMS_STRIPPED");
			if (AND(Characteristics, 0x0010))
				buf += string.Format(format, "AGGRESIVE_WS_TRIM");
			if (AND(Characteristics, 0x0020))
				buf += string.Format(format, "LARGE_ADDRESS_AWARE");
			if (AND(Characteristics, 0x0080))
				buf += string.Format(format, "BYTES_REVERSED_LO");
			if (AND(Characteristics, 0x0100))
				buf += string.Format(format, "32BIT_MACHINE");
			if (AND(Characteristics, 0x0200))
				buf += string.Format(format, "DEBUG_STRIPPED");
			if (AND(Characteristics, 0x0400))
				buf += string.Format(format, "REMOVABLE_RUN_FROM_SWAP");
			if (AND(Characteristics, 0x0800))
				buf += string.Format(format, "NET_RUN_FROM_SWAP");
			if (AND(Characteristics, 0x1000))
				buf += string.Format(format, "SYSTEM");
			if (AND(Characteristics, 0x2000))
				buf += string.Format(format, "DLL");
			if (AND(Characteristics, 0x4000))
				buf += string.Format(format, "UP_SYSTEM_ONLY");
			if (AND(Characteristics, 0x8000))
				buf += string.Format(format, "BYTES_REVERSED_HI");
			return buf;
		}
		
		public void PrintFileHeader()
		{
			const string format =
				"->File Header\n"+
				"   Machine:               0x{0}  ({7})\n"+
				"   NumberOfSections:      0x{1}\n"+
				"   TimeDateStamp:         0x{2}  (GMT: {8})\n"+
				"   PointerToSymbolTable:  0x{3}\n"+
				"   NumberOfSymbols:       0x{4}\n"+
				"   SizeOfOptionalHeader:  0x{5}\n"+
				"   Characteristics:       0x{6}\n"+
				"{9}"
			;
			
			string buf = string.Format(
				format,
				FH_Machine.ToString("X4"),
				FH_NumberOfSections.ToString("X4"),
				FH_TimeDateStamp.ToString("X8"),
				FH_PointerToSymbolTable.ToString("X8"),
				FH_NumberOfSymbols.ToString("X8"),
				FH_SizeOfOptionalHeader.ToString("X4"),
				FH_Characteristics.ToString("X4"),
				MachineHint(FH_Machine),
				TimeDateStampHint(FH_TimeDateStamp),
				FHCharacteristicsHint(FH_Characteristics)
			);
			
			Console.WriteLine(buf);
		}
		
		string OHMagicHint(ushort Magic)
		{
			switch (Magic) 
			{
					case 0x10b: return "HDR32_MAGIC";
					case 0x20b: return "HDR64_MAGIC";
					case 0x107: return "ROM_MAGIC";
					default: return "N/A";
			}
		}
		
		string OHVersionHint(ushort maj, ushort min)
		{
			return string.Format("{0}.{1}", maj, min.ToString("D2"));
		}
		
		string OHSubsystemHint(ushort Subsystem)
		{
			switch (Subsystem) 
			{
					case 1:return "NATIVE";
					case 2:return "WINDOWS_GUI";
					case 3:return "WINDOWS_CUI";
					case 5:return "OS2_CUI";
					case 7:return "POSIX_CUI";
					case 9:return "WINDOWS_CE_GUI";
					case 10:return "EFI_APPLICATION";
					case 11:return "EFI_BOOT_SERVICE_DRIVER";
					case 12:return "EFI_RUNTIME_DRIVER";
					case 13:return "EFI_ROM";
					case 14:return "XBOX";
					case 16:return "WINDOWS_BOOT_APPLICATION";
					default:return "UNKNOWN";
			}
		}
		
		public void PrintOptionalHeader()
		{
			const string format =
				"->Optional Header\n"+
				"   Magic:                        0x{0}  ({30})\n"+
				"   MajorLinkerVersion:           0x{1}\n"+
				"   MinorLinkerVersion:           0x{2}  -> {31}\n"+
				"   SizeOfCode:                   0x{3}\n"+
				"   SizeOfInitializedData:        0x{4}\n"+
				"   SizeOfUninitializedData:      0x{5}\n"+
				"   AddressOfEntryPoint:          0x{6}\n"+
				"   BaseOfCode:                   0x{7}\n"+
				"   BaseOfData:                   0x{8}\n"+
				"   ImageBase:                    0x{9}\n"+
				"   SectionAlignment:             0x{10}\n"+
				"   FileAlignment:                0x{11}\n"+
				"   MajorOperatingSystemVersion:  0x{12}\n"+
				"   MinorOperatingSystemVersion:  0x{13}  -> {32}\n"+
				"   MajorImageVersion:            0x{14}\n"+
				"   MinorImageVersion:            0x{15}  -> {33}\n"+
				"   MajorSubsystemVersion:        0x{16}\n"+
				"   MinorSubsystemVersion:        0x{17}  -> {34}\n"+
				"   Win32VersionValue:            0x{18}\n"+
				"   SizeOfImage:                  0x{19}\n"+
				"   SizeOfHeaders:                0x{20}\n"+
				"   CheckSum:                     0x{21}\n"+
				"   Subsystem:                    0x{22}  ({35})\n"+
				"   DllCharacteristics:           0x{23}\n"+
				"   SizeOfStackReserve:           0x{24}\n"+
				"   SizeOfStackCommit:            0x{25}\n"+
				"   SizeOfHeapReserve:            0x{26}\n"+
				"   SizeOfHeapCommit:             0x{27}\n"+
				"   LoaderFlags:                  0x{28}\n"+
				"   NumberOfRvaAndSizes:          0x{29}\n"
			;
			
			bool OH32 = (FH_SizeOfOptionalHeader == 224);
			
			string buf = string.Format(
				format,
				OH_Magic.ToString("X4"),
				OH_MajorLinkerVersion.ToString("X2"),
				OH_MinorLinkerVersion.ToString("X2"),
				OH_SizeOfCode.ToString("X8"),
				OH_SizeOfInitializedData.ToString("X8"),
				OH_SizeOfUninitializedData.ToString("X8"),
				OH_AddressOfEntryPoint.ToString("X8"),
				OH_BaseOfCode.ToString("X8"),
				(OH32)?OH_BaseOfData.ToString("X8"): "N/A",
				OH_ImageBase.ToString((OH32)?"X8":"X16"),
				OH_SectionAlignment.ToString("X8"),
				OH_FileAlignment.ToString("X8"),
				OH_MajorOperatingSystemVersion.ToString("X4"),
				OH_MinorOperatingSystemVersion.ToString("X4"),
				OH_MajorImageVersion.ToString("X4"),
				OH_MinorImageVersion.ToString("X4"),
				OH_MajorSubsystemVersion.ToString("X4"),
				OH_MinorSubsystemVersion.ToString("X4"),
				OH_Win32VersionValue.ToString("X8"),
				OH_SizeOfImage.ToString("X8"),
				OH_SizeOfHeaders.ToString("X8"),
				OH_CheckSum.ToString("X8"),
				OH_Subsystem.ToString("X4"),
				OH_DllCharacteristics.ToString("X4"),
				OH_SizeOfStackReserve.ToString((OH32)?"X8":"X16"),
				OH_SizeOfStackCommit.ToString((OH32)?"X8":"X16"),
				OH_SizeOfHeapReserve.ToString((OH32)?"X8":"X16"),
				OH_SizeOfHeapCommit.ToString((OH32)?"X8":"X16"),
				OH_LoaderFlags.ToString("X8"),
				OH_NumberOfRvaAndSizes.ToString("X8"),
				OHMagicHint(OH_Magic),
				OHVersionHint(OH_MajorLinkerVersion, OH_MinorLinkerVersion),
				OHVersionHint
				(
				OH_MajorOperatingSystemVersion,
				OH_MinorOperatingSystemVersion
				),
				OHVersionHint(OH_MajorImageVersion, OH_MinorImageVersion),
				OHVersionHint
				(
					OH_MajorSubsystemVersion, OH_MinorSubsystemVersion
				),
				OHSubsystemHint(OH_Subsystem)
			);
			
			Console.WriteLine(buf);
			
			PrintDataDirectory();
		}
		
		string SHNameHint(uint VirtualAddress)
		{
			if (VirtualAddress != 0)
				for (int i = 0; i < FH_NumberOfSections; i++) 
				{
					if (SH_VirtualAddress[i] == VirtualAddress) 
						return string.Format(
							"(\"{0}\")",
							Encoding.UTF8.GetString(SH_Name[i]).
							Replace("\0", default(string))
						);
				}
			return default(string);
		}
		
		public void  PrintDataDirectory()
		{
			const string format = "0x{0} 0x{1}  {2}\n";
			
			string buf =
				"   DataDirectory (16)            RVA        Size\n"+
				"   -------------                 ---------- ----------\n";
			string[] names = {
				"   ExportTable                   ",
				"   ImportTable                   ",
				"   Resource                      ",
				"   Exception                     ",
				"   Security                      ",
				"   Relocation                    ",
				"   Debug                         ",
				"   Copyright                     ",
				"   GlobalPtr                     ",
				"   TLSTable                      ",
				"   LoadConfig                    ",
				"   BoundImport                   ",
				"   IAT                           ",
				"   DelayImport                   ",
				"   COM                           ",
				"   Reserved                      "
			};
			
			for (int i = 0; i < 16; i++) {
				buf += string.Format(
						names[i] + format,
						OH_DD_VirtualAddress[i].ToString("X8"),
						OH_DD_Size[i].ToString("X8"),
						SHNameHint(OH_DD_VirtualAddress[i])
					);
			}
			
			Console.WriteLine(buf);
		}
		
		public void PrintNtHeader()
		{
			Console.WriteLine(
				"->NT Headers\n"+
				"   Signature:        {0}",
				NH_Signature.ToString("X8")
			);
			PrintFileHeader();
			PrintOptionalHeader();
		}
		
		void GetSectionHeader(string fileName)
		{
			using (FileStream fs = new FileStream(fileName, FileMode.Open)) 
			{
				bool OH32 = (FH_SizeOfOptionalHeader == 224);
				fs.Position += DH_e_lfanew + ((OH32)?248: 264);
				SH_Name = new byte[FH_NumberOfSections][];
				SH_Misc = new uint[FH_NumberOfSections];
				SH_VirtualAddress = new uint[FH_NumberOfSections];
				SH_SizeOfRawData = new uint[FH_NumberOfSections];
				SH_PointerToRawData = new uint[FH_NumberOfSections];
				SH_PointerToRelocations = new uint[FH_NumberOfSections];
				SH_PointerToLinenumbers = new uint[FH_NumberOfSections];
				SH_NumberOfRelocations = new ushort[FH_NumberOfSections];
				SH_NumberOfLinenumbers = new ushort[FH_NumberOfSections];
				SH_Characteristics = new uint[FH_NumberOfSections];
				for (int i = 0; i < FH_NumberOfSections; i++) 
				{
					SH_Name[i] = new byte[8];
					fs.Read(SH_Name[i], 0, 8);
					SH_Misc[i] = ReadDword(fs);
					SH_VirtualAddress[i] = ReadDword(fs);
					SH_SizeOfRawData[i] = ReadDword(fs);
					SH_PointerToRawData[i] = ReadDword(fs);
					SH_PointerToRelocations[i] = ReadDword(fs);
					SH_PointerToLinenumbers[i] = ReadDword(fs);
					SH_NumberOfRelocations[i] = ReadWord(fs);
					SH_NumberOfLinenumbers[i] = ReadWord(fs);
					SH_Characteristics[i] = ReadDword(fs);
				}
			}
		}
		
		public void SetSectionHeader(
			byte[][] Name, uint[] Misc, uint[] VirtualAddress,
			uint[] SizeOfRawData, uint[] PointerToRawData,
			uint[] PointerToRelocations, uint[] PointerToLinenumbers,
			ushort[] NumberOfRelocations, ushort[] NumberOfLinenumbers,
			uint[] Characteristics
		)
		{
			SH_Name = Name;
			SH_Misc = Misc;
			SH_VirtualAddress = VirtualAddress;
			SH_SizeOfRawData = SizeOfRawData;
			SH_PointerToRawData = PointerToRawData;
			SH_PointerToRelocations = PointerToRelocations;
			SH_PointerToLinenumbers = PointerToLinenumbers;
			SH_NumberOfRelocations = NumberOfRelocations;
			SH_NumberOfLinenumbers = NumberOfLinenumbers;
			SH_Characteristics = Characteristics;
		}
		
		string SHCharacteristicsHint(uint Characteristics)
		{
			string buf = default(string);
			int i = 0;
			string[] array = new string[10];
			if (AND(Characteristics, 0x00000020)) 
				array[i++] = "CODE";
			if(AND(Characteristics, 0x00000040))
				array[i++] = "INITIALIZED_DATA";
			if(AND(Characteristics, 0x00000080))
				array[i++] = "UNINITIALIZED_DATA";
			if(AND(Characteristics, 0x02000000))
				array[i++] = "DISCARDABLE";
			if(AND(Characteristics, 0x04000000))
				array[i++] = "NOT_CACHED";
			if(AND(Characteristics, 0x08000000))
				array[i++] = "NOT_PAGED";
			if(AND(Characteristics, 0x10000000))
				array[i++] = "SHARED";
			if(AND(Characteristics, 0x20000000))
				array[i++] = "EXECUTE";
			if(AND(Characteristics, 0x40000000))
				array[i++] = "READ";
			if(AND(Characteristics, 0x80000000))
				array[i++] = "WRITE";
			for (int j = 0; j < i; j++) 
			{
				buf += array[j];
				if (j < i - 1)
					buf += ", ";
			}
			return buf;
		}
		
		public void PrintSectionHeader()
		{
			string format =
				"   {0}. item:\n"+
				"    Name:                  {1}\n"+
				"    VirtualSize:           0x{2}\n"+
				"    VirtualAddress:        0x{3}\n"+
				"    SizeOfRawData:         0x{4}\n"+
				"    PointerToRawData:      0x{5}\n"+
				"    PointerToRelocations:  0x{6}\n"+
				"    PointerToLinenumbers:  0x{7}\n"+
				"    NumberOfRelocations:   0x{8}\n"+
				"    NumberOfLinenumbers:   0x{9}\n"+
				"    Characteristics:       0x{10}\n"+
				"    ({11})\n\n"
			;
			
			string buf = "->Section Header Table\n";
			
			for (int i = 0; i < FH_NumberOfSections; i++) 
			{
				buf += string.Format(
					format,
					i + 1,
					Encoding.UTF8.GetString(SH_Name[i]),
					SH_Misc[i].ToString("X8"),
					SH_VirtualAddress[i].ToString("X8"),
					SH_SizeOfRawData[i].ToString("X8"),
					SH_PointerToRawData[i].ToString("X8"),
					SH_PointerToRelocations[i].ToString("X8"),
					SH_PointerToLinenumbers[i].ToString("X8"),
					SH_NumberOfRelocations[i].ToString("X4"),
					SH_NumberOfLinenumbers[i].ToString("X4"),
					SH_Characteristics[i].ToString("X8"),
					SHCharacteristicsHint(SH_Characteristics[i])
				);
			}
			
			Console.WriteLine(buf);
		}
		
		uint EDVirtualAddressToRawPtr(uint VirtualAddress)
		{
			if(VirtualAddress != 0)
				for (int i = 0; i < FH_NumberOfSections; i++)
					if (VirtualAddress == SH_VirtualAddress[i])
						return SH_PointerToRawData[i];
			return 0;
		}
		
		string ReadToNull(FileStream fs)
		{
			string value = default(string);
			byte[] b = new byte[1];
			while ((b[0] = (byte)fs.ReadByte()) != 0)
				value += Encoding.UTF8.GetString(b);
			return value;
		}
		
		ushort EDGetOrdinal(ushort NameOrdinal)
		{
			uint value = NameOrdinal + ED_Base;
			return (ushort) value;
		}
		
		void GetExportDirectory(string fileName)
		{
			using (FileStream fs = new FileStream(fileName, FileMode.Open))
			{
				uint offset = EDVirtualAddressToRawPtr(
					OH_DD_VirtualAddress[0]
				);
				
				if (offset == 0) 
					return;
				
				fs.Position = offset;
				
				ED_Characteristics = ReadDword(fs);
				ED_TimeDateStamp = ReadDword(fs);
				ED_MajorVersion = ReadWord(fs);
				ED_MinorVersion = ReadWord(fs);
				ED_Name = ReadDword(fs);
				ED_Base = ReadDword(fs);
				ED_NumberOfFunctions = ReadDword(fs);
				ED_NumberOfNames = ReadDword(fs);
				ED_AddressOfFunctions = ReadDword(fs);
				ED_AddressOfNames = ReadDword(fs);
				ED_AddressOfNameOrdinals = ReadDword(fs);
				
				fs.Position = offset + ED_AddressOfFunctions -
					OH_DD_VirtualAddress[0];
				
				ED_AddressOfFunctionsValues = new uint[ED_NumberOfFunctions];
				for (int i = 0; i < ED_NumberOfFunctions; i++) 
					ED_AddressOfFunctionsValues[i] = ReadDword(fs);
				
				fs.Position = offset + ED_AddressOfNames -
					OH_DD_VirtualAddress[0];
				
				ED_AddressOfNamesValues = new uint[ED_NumberOfNames];
				for (int i = 0; i < ED_NumberOfNames; i++)
					ED_AddressOfNamesValues[i] = ReadDword(fs);
				
				fs.Position = offset + ED_AddressOfNameOrdinals -
					OH_DD_VirtualAddress[0];
				
				ED_AddressOfNameOrdinalsValues = new ushort[ED_NumberOfNames];
				for (int i = 0; i < ED_NumberOfNames; i++)
					ED_AddressOfNameOrdinalsValues[i] = ReadWord(fs);
				
				fs.Position = offset + ED_Name - OH_DD_VirtualAddress[0];
				
				ED_NameValue = ReadToNull(fs);
				
				ED_FunctionNamesValues = new string[ED_NumberOfNames];
				
				for (int i = 0; i < ED_NumberOfNames; i++) 
				{
					fs.Position = offset + ED_AddressOfNamesValues[i] -
						OH_DD_VirtualAddress[0];
					ED_FunctionNamesValues[i] = ReadToNull(fs);
				}
			}
		}
		
		public void SetExportDirectory(
			uint Characteristics, uint TimeDateStamp, ushort MajorVersion,
			ushort MinorVersion, uint Name, uint Base, 
			uint NumberOfFunctions, uint NumberOfNames,
			uint AddressOfFunctions, uint AddressOfNames,
			uint AddressOfNameOrdinals
		)
		{
			ED_Characteristics = Characteristics;
			ED_TimeDateStamp = TimeDateStamp;
			ED_MajorVersion = MajorVersion;
			ED_MinorVersion = MinorVersion;
			ED_Name = Name;
			ED_Base = Base;
			ED_NumberOfFunctions = NumberOfFunctions;
			ED_NumberOfNames = NumberOfNames;
			ED_AddressOfFunctions = AddressOfFunctions;
			ED_AddressOfNames = AddressOfNames;
			ED_AddressOfNameOrdinals = AddressOfNameOrdinals;
		}
		
		public void PrintExportDirectory()
		{
			string format = 
				"->Export Table\n"+
				"   Characteristics:        0x{0}\n"+
				"   TimeDateStamp:          0x{1}  (GMT: {11})\n"+
				"   MajorVersion:           0x{2}\n"+
				"   MinorVersion:           0x{3}  -> {12}\n"+
				"   Name:                   0x{4}  {13}\n"+
				"   Base:                   0x{5}\n"+
				"   NumberOfFunctions:      0x{6}\n"+
				"   NumberOfNames:          0x{7}\n"+
				"   AddressOfFunctions:     0x{8}\n"+
				"   AddressOfNames:         0x{9}\n"+
				"   AddressOfNameOrdinals:  0x{10}\n\n"+
				"   Ordinal RVA        Symbol Name\n"+
				"   ------- ---------- ----------------------------------\n"
			;
			
			string buf = string.Format(
				format,
				ED_Characteristics.ToString("X8"),
				ED_TimeDateStamp.ToString("X8"),
				ED_MajorVersion.ToString("X4"),
				ED_MinorVersion.ToString("X4"),
				ED_Name.ToString("X8"),
				ED_Base.ToString("X8"),
				ED_NumberOfFunctions.ToString("X8"),
				ED_NumberOfNames.ToString("X8"),
				ED_AddressOfFunctions.ToString("X8"),
				ED_AddressOfNames.ToString("X8"),
				ED_AddressOfNameOrdinals.ToString("X8"),
				TimeDateStampHint(ED_TimeDateStamp),
				OHVersionHint(ED_MajorVersion, ED_MinorVersion),
				"(\"" + ED_NameValue + "\")"
			);
			
			format = " \t {0} 0x{1} {2}\n";
			
			for (int i = 0; i < ED_NumberOfNames; i++) 
			{
				buf += string.Format(
					format,
					EDGetOrdinal(ED_AddressOfNameOrdinalsValues[i])
						.ToString(""),
					ED_AddressOfFunctionsValues[i].ToString("X8"),
					ED_FunctionNamesValues[i]
				);
			}
			
			Console.WriteLine(buf);
		}
	}
}
