@ stdcall BindImage(str str str)
@ stdcall BindImageEx(long str str str ptr)
@ stdcall CheckSumMappedFile(ptr long ptr ptr)
@ stdcall EnumerateLoadedModules(long ptr ptr)
@ stdcall FindDebugInfoFile(str str str)
@ stdcall FindExecutableImage(str str str)
@ stdcall GetImageConfigInformation(ptr ptr)
@ stdcall GetImageUnusedHeaderBytes(ptr ptr)
@ stdcall GetTimestampForLoadedLibrary(long)
@ stdcall ImageAddCertificate(long ptr ptr)
@ stdcall ImageDirectoryEntryToData(ptr long long ptr)
@ stdcall ImageEnumerateCertificates(long long ptr ptr long)
@ stdcall ImageGetCertificateData(long long ptr ptr)
@ stdcall ImageGetCertificateHeader(long long ptr)
@ stdcall ImageGetDigestStream(long long ptr long)
@ stdcall ImageLoad(str str)
@ stdcall ImageNtHeader(ptr)
@ stdcall ImageRemoveCertificate(long long)
@ stdcall ImageRvaToSection(ptr ptr long)
@ stdcall ImageRvaToVa(ptr ptr long ptr)
@ stdcall ImageUnload(ptr)
@ stdcall ImagehlpApiVersion()
@ stdcall ImagehlpApiVersionEx(ptr)
@ stdcall MakeSureDirectoryPathExists(str)
@ stdcall MapAndLoad(str str ptr long long)
@ stdcall MapDebugInformation(long str str long)
@ stdcall MapFileAndCheckSumA(str ptr ptr)
@ stdcall MapFileAndCheckSumW(wstr ptr ptr)
@ stub  MarkImageAsRunFromSwap
@ stdcall ReBaseImage(str str long long long long ptr ptr ptr ptr long)
@ stdcall RemovePrivateCvSymbolic(ptr ptr ptr)
@ stdcall RemoveRelocations(ptr)
@ stdcall SearchTreeForFile(str str str)
@ stdcall SetImageConfigInformation(ptr ptr)
@ stdcall SplitSymbols(str str str long)
@ stdcall StackWalk(long long long ptr ptr ptr ptr ptr ptr)
@ stdcall SymCleanup(long)
@ stdcall SymEnumerateModules(long ptr ptr)
@ stdcall SymEnumerateSymbols(long long ptr ptr)
@ stdcall SymFunctionTableAccess(long long)
@ stdcall SymGetModuleBase(long long)
@ stdcall SymGetModuleInfo(long long ptr)
@ stdcall SymGetOptions()
@ stdcall SymGetSearchPath(long str long)
@ stdcall SymGetSymFromAddr(long long ptr ptr)
@ stdcall SymGetSymFromName(long str ptr)
@ stdcall SymGetSymNext(long ptr)
@ stdcall SymGetSymPrev(long ptr)
@ stdcall SymInitialize(long str long)
@ stdcall SymLoadModule(long long str str long long)
@ stdcall SymRegisterCallback(long ptr ptr)
@ stdcall SymSetOptions(long)
@ stdcall SymSetSearchPath(long str)
@ stdcall SymUnDName(ptr str long)
@ stdcall SymUnloadModule(long long)
@ stdcall TouchFileTimes(long ptr)
@ stdcall UnDecorateSymbolName(str str long long)
@ stdcall UnMapAndLoad(ptr)
@ stdcall UnmapDebugInformation(ptr)
@ stdcall UpdateDebugInfoFile(str str str ptr)
@ stdcall UpdateDebugInfoFileEx(str str str ptr long)
