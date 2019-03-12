/* 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * (c) 2019 Jannik Vogel
 *
 */
package xbe;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.util.bin.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.demangler.*;
import ghidra.app.util.importer.*;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.MemoryBlockUtil;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.Option;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class XbeLoader extends AbstractLibrarySupportLoader {

	//FIXME: Add type information?
	//FIXME: Move to analysis pass?
	private static final String[] kernelExportNames = {
		"", // 0
		"AvGetSavedDataAddress", // 1
		"AvSendTVEncoderOption", // 2
		"AvSetDisplayMode", // 3
		"AvSetSavedDataAddress", // 4
		"DbgBreakPoint", // 5
		"DbgBreakPointWithStatus", // 6
		"DbgLoadImageSymbols", // 7
		"DbgPrint", // 8
		"HalReadSMCTrayState", // 9
		"DbgPrompt", // 10
		"DbgUnLoadImageSymbols", // 11
		"ExAcquireReadWriteLockExclusive", // 12
		"ExAcquireReadWriteLockShared", // 13
		"ExAllocatePool", // 14
		"ExAllocatePoolWithTag", // 15
		"ExEventObjectType", // 16
		"ExFreePool", // 17
		"ExInitializeReadWriteLock", // 18
		"ExInterlockedAddLargeInteger", // 19
		"ExInterlockedAddLargeStatistic", // 20
		"ExInterlockedCompareExchange64", // 21
		"ExMutantObjectType", // 22
		"ExQueryPoolBlockSize", // 23
		"ExQueryNonVolatileSetting", // 24
		"ExReadWriteRefurbInfo", // 25
		"ExRaiseException", // 26
		"ExRaiseStatus", // 27
		"ExReleaseReadWriteLock", // 28
		"ExSaveNonVolatileSetting", // 29
		"ExSemaphoreObjectType", // 30
		"ExTimerObjectType", // 31
		"ExfInterlockedInsertHeadList", // 32
		"ExfInterlockedInsertTailList", // 33
		"ExfInterlockedRemoveHeadList", // 34
		"FscGetCacheSize", // 35
		"FscInvalidateIdleBlocks", // 36
		"FscSetCacheSize", // 37
		"HalClearSoftwareInterrupt", // 38
		"HalDisableSystemInterrupt", // 39
		"HalDiskCachePartitionCount", // 40
		"HalDiskModelNumber", // 41
		"HalDiskSerialNumber", // 42
		"HalEnableSystemInterrupt", // 43
		"HalGetInterruptVector", // 44
		"HalReadSMBusValue", // 45
		"HalReadWritePCISpace", // 46
		"HalRegisterShutdownNotification", // 47
		"HalRequestSoftwareInterrupt", // 48
		"HalReturnToFirmware", // 49
		"HalWriteSMBusValue", // 50
		"InterlockedCompareExchange", // 51
		"InterlockedDecrement", // 52
		"InterlockedIncrement", // 53
		"InterlockedExchange", // 54
		"InterlockedExchangeAdd", // 55
		"InterlockedFlushSList", // 56
		"InterlockedPopEntrySList", // 57
		"InterlockedPushEntrySList", // 58
		"IoAllocateIrp", // 59
		"IoBuildAsynchronousFsdRequest", // 60
		"IoBuildDeviceIoControlRequest", // 61
		"IoBuildSynchronousFsdRequest", // 62
		"IoCheckShareAccess", // 63
		"IoCompletionObjectType", // 64
		"IoCreateDevice", // 65
		"IoCreateFile", // 66
		"IoCreateSymbolicLink", // 67
		"IoDeleteDevice", // 68
		"IoDeleteSymbolicLink", // 69
		"IoDeviceObjectType", // 70
		"IoFileObjectType", // 71
		"IoFreeIrp", // 72
		"IoInitializeIrp", // 73
		"IoInvalidDeviceRequest", // 74
		"IoQueryFileInformation", // 75
		"IoQueryVolumeInformation", // 76
		"IoQueueThreadIrp", // 77
		"IoRemoveShareAccess", // 78
		"IoSetIoCompletion", // 79
		"IoSetShareAccess", // 80
		"IoStartNextPacket", // 81
		"IoStartNextPacketByKey", // 82
		"IoStartPacket", // 83
		"IoSynchronousDeviceIoControlRequest", // 84
		"IoSynchronousFsdRequest", // 85
		"IofCallDriver", // 86
		"IofCompleteRequest", // 87
		"KdDebuggerEnabled", // 88
		"KdDebuggerNotPresent", // 89
		"IoDismountVolume", // 90
		"IoDismountVolumeByName", // 91
		"KeAlertResumeThread", // 92
		"KeAlertThread", // 93
		"KeBoostPriorityThread", // 94
		"KeBugCheck", // 95
		"KeBugCheckEx", // 96
		"KeCancelTimer", // 97
		"KeConnectInterrupt", // 98
		"KeDelayExecutionThread", // 99
		"KeDisconnectInterrupt", // 100
		"KeEnterCriticalRegion", // 101
		"MmGlobalData", // 102
		"KeGetCurrentIrql", // 103
		"KeGetCurrentThread", // 104
		"KeInitializeApc", // 105
		"KeInitializeDeviceQueue", // 106
		"KeInitializeDpc", // 107
		"KeInitializeEvent", // 108
		"KeInitializeInterrupt", // 109
		"KeInitializeMutant", // 110
		"KeInitializeQueue", // 111
		"KeInitializeSemaphore", // 112
		"KeInitializeTimerEx", // 113
		"KeInsertByKeyDeviceQueue", // 114
		"KeInsertDeviceQueue", // 115
		"KeInsertHeadQueue", // 116
		"KeInsertQueue", // 117
		"KeInsertQueueApc", // 118
		"KeInsertQueueDpc", // 119
		"KeInterruptTime", // 120
		"KeIsExecutingDpc", // 121
		"KeLeaveCriticalRegion", // 122
		"KePulseEvent", // 123
		"KeQueryBasePriorityThread", // 124
		"KeQueryInterruptTime", // 125
		"KeQueryPerformanceCounter", // 126
		"KeQueryPerformanceFrequency", // 127
		"KeQuerySystemTime", // 128
		"KeRaiseIrqlToDpcLevel", // 129
		"KeRaiseIrqlToSynchLevel", // 130
		"KeReleaseMutant", // 131
		"KeReleaseSemaphore", // 132
		"KeRemoveByKeyDeviceQueue", // 133
		"KeRemoveDeviceQueue", // 134
		"KeRemoveEntryDeviceQueue", // 135
		"KeRemoveQueue", // 136
		"KeRemoveQueueDpc", // 137
		"KeResetEvent", // 138
		"KeRestoreFloatingPointState", // 139
		"KeResumeThread", // 140
		"KeRundownQueue", // 141
		"KeSaveFloatingPointState", // 142
		"KeSetBasePriorityThread", // 143
		"KeSetDisableBoostThread", // 144
		"KeSetEvent", // 145
		"KeSetEventBoostPriority", // 146
		"KeSetPriorityProcess", // 147
		"KeSetPriorityThread", // 148
		"KeSetTimer", // 149
		"KeSetTimerEx", // 150
		"KeStallExecutionProcessor", // 151
		"KeSuspendThread", // 152
		"KeSynchronizeExecution", // 153
		"KeSystemTime", // 154
		"KeTestAlertThread", // 155
		"KeTickCount", // 156
		"KeTimeIncrement", // 157
		"KeWaitForMultipleObjects", // 158
		"KeWaitForSingleObject", // 159
		"KfRaiseIrql", // 160
		"KfLowerIrql", // 161
		"KiBugCheckData", // 162_PTR[5]
		"KiUnlockDispatcherDatabase", // 163
		"LaunchDataPage", // 164
		"MmAllocateContiguousMemory", // 165
		"MmAllocateContiguousMemoryEx", // 166
		"MmAllocateSystemMemory", // 167
		"MmClaimGpuInstanceMemory", // 168
		"MmCreateKernelStack", // 169
		"MmDeleteKernelStack", // 170
		"MmFreeContiguousMemory", // 171
		"MmFreeSystemMemory", // 172
		"MmGetPhysicalAddress", // 173
		"MmIsAddressValid", // 174
		"MmLockUnlockBufferPages", // 175
		"MmLockUnlockPhysicalPage", // 176
		"MmMapIoSpace", // 177
		"MmPersistContiguousMemory", // 178
		"MmQueryAddressProtect", // 179
		"MmQueryAllocationSize", // 180
		"MmQueryStatistics", // 181
		"MmSetAddressProtect", // 182
		"MmUnmapIoSpace", // 183
		"NtAllocateVirtualMemory", // 184
		"NtCancelTimer", // 185
		"NtClearEvent", // 186
		"NtClose", // 187
		"NtCreateDirectoryObject", // 188
		"NtCreateEvent", // 189
		"NtCreateFile", // 190
		"NtCreateIoCompletion", // 191
		"NtCreateMutant", // 192
		"NtCreateSemaphore", // 193
		"NtCreateTimer", // 194
		"NtDeleteFile", // 195
		"NtDeviceIoControlFile", // 196
		"NtDuplicateObject", // 197
		"NtFlushBuffersFile", // 198
		"NtFreeVirtualMemory", // 199
		"NtFsControlFile", // 200
		"NtOpenDirectoryObject", // 201
		"NtOpenFile", // 202
		"NtOpenSymbolicLinkObject", // 203
		"NtProtectVirtualMemory", // 204
		"NtPulseEvent", // 205
		"NtQueueApcThread", // 206
		"NtQueryDirectoryFile", // 207
		"NtQueryDirectoryObject", // 208
		"NtQueryEvent", // 209
		"NtQueryFullAttributesFile", // 210
		"NtQueryInformationFile", // 211
		"NtQueryIoCompletion", // 212
		"NtQueryMutant", // 213
		"NtQuerySemaphore", // 214
		"NtQuerySymbolicLinkObject", // 215
		"NtQueryTimer", // 216
		"NtQueryVirtualMemory", // 217
		"NtQueryVolumeInformationFile", // 218
		"NtReadFile", // 219
		"NtReadFileScatter", // 220
		"NtReleaseMutant", // 221
		"NtReleaseSemaphore", // 222
		"NtRemoveIoCompletion", // 223
		"NtResumeThread", // 224
		"NtSetEvent", // 225
		"NtSetInformationFile", // 226
		"NtSetIoCompletion", // 227
		"NtSetSystemTime", // 228
		"NtSetTimerEx", // 229
		"NtSignalAndWaitForSingleObjectEx", // 230
		"NtSuspendThread", // 231
		"NtUserIoApcDispatcher", // 232
		"NtWaitForSingleObject", // 233
		"NtWaitForSingleObjectEx", // 234
		"NtWaitForMultipleObjectsEx", // 235
		"NtWriteFile", // 236
		"NtWriteFileGather", // 237
		"NtYieldExecution", // 238
		"ObCreateObject", // 239
		"ObDirectoryObjectType", // 240
		"ObInsertObject", // 241
		"ObMakeTemporaryObject", // 242
		"ObOpenObjectByName", // 243
		"ObOpenObjectByPointer", // 244
		"ObpObjectHandleTable", // 245
		"ObReferenceObjectByHandle", // 246
		"ObReferenceObjectByName", // 247
		"ObReferenceObjectByPointer", // 248
		"ObSymbolicLinkObjectType", // 249
		"ObfDereferenceObject", // 250
		"ObfReferenceObject", // 251
		"PhyGetLinkState", // 252
		"PhyInitialize", // 253
		"PsCreateSystemThread", // 254
		"PsCreateSystemThreadEx", // 255
		"PsQueryStatistics", // 256
		"PsSetCreateThreadNotifyRoutine", // 257
		"PsTerminateSystemThread", // 258
		"PsThreadObjectType", // 259
		"RtlAnsiStringToUnicodeString", // 260
		"RtlAppendStringToString", // 261
		"RtlAppendUnicodeStringToString", // 262
		"RtlAppendUnicodeToString", // 263
		"RtlAssert", // 264
		"RtlCaptureContext", // 265
		"RtlCaptureStackBackTrace", // 266
		"RtlCharToInteger", // 267
		"RtlCompareMemory", // 268
		"RtlCompareMemoryUlong", // 269
		"RtlCompareString", // 270
		"RtlCompareUnicodeString", // 271
		"RtlCopyString", // 272
		"RtlCopyUnicodeString", // 273
		"RtlCreateUnicodeString", // 274
		"RtlDowncaseUnicodeChar", // 275
		"RtlDowncaseUnicodeString", // 276
		"RtlEnterCriticalSection", // 277
		"RtlEnterCriticalSectionAndRegion", // 278
		"RtlEqualString", // 279
		"RtlEqualUnicodeString", // 280
		"RtlExtendedIntegerMultiply", // 281
		"RtlExtendedLargeIntegerDivide", // 282
		"RtlExtendedMagicDivide", // 283
		"RtlFillMemory", // 284
		"RtlFillMemoryUlong", // 285
		"RtlFreeAnsiString", // 286
		"RtlFreeUnicodeString", // 287
		"RtlGetCallersAddress", // 288
		"RtlInitAnsiString", // 289
		"RtlInitUnicodeString", // 290
		"RtlInitializeCriticalSection", // 291
		"RtlIntegerToChar", // 292
		"RtlIntegerToUnicodeString", // 293
		"RtlLeaveCriticalSection", // 294
		"RtlLeaveCriticalSectionAndRegion", // 295
		"RtlLowerChar", // 296
		"RtlMapGenericMask", // 297
		"RtlMoveMemory", // 298
		"RtlMultiByteToUnicodeN", // 299
		"RtlMultiByteToUnicodeSize", // 300
		"RtlNtStatusToDosError", // 301
		"RtlRaiseException", // 302
		"RtlRaiseStatus", // 303
		"RtlTimeFieldsToTime", // 304
		"RtlTimeToTimeFields", // 305
		"RtlTryEnterCriticalSection", // 306
		"RtlUlongByteSwap", // 307
		"RtlUnicodeStringToAnsiString", // 308
		"RtlUnicodeStringToInteger", // 309
		"RtlUnicodeToMultiByteN", // 310
		"RtlUnicodeToMultiByteSize", // 311
		"RtlUnwind", // 312
		"RtlUpcaseUnicodeChar", // 313
		"RtlUpcaseUnicodeString", // 314
		"RtlUpcaseUnicodeToMultiByteN", // 315
		"RtlUpperChar", // 316
		"RtlUpperString", // 317
		"RtlUshortByteSwap", // 318
		"RtlWalkFrameChain", // 319
		"RtlZeroMemory", // 320
		"XboxEEPROMKey", // 321
		"XboxHardwareInfo", // 322
		"XboxHDKey", // 323
		"XboxKrnlVersion", // 324
		"XboxSignatureKey", // 325
		"XeImageFileName", // 326
		"XeLoadSection", // 327
		"XeUnloadSection", // 328
		"READ_PORT_BUFFER_UCHAR", // 329
		"READ_PORT_BUFFER_USHORT", // 330
		"READ_PORT_BUFFER_ULONG", // 331
		"WRITE_PORT_BUFFER_UCHAR", // 332
		"WRITE_PORT_BUFFER_USHORT", // 333
		"WRITE_PORT_BUFFER_ULONG", // 334
		"XcSHAInit", // 335
		"XcSHAUpdate", // 336
		"XcSHAFinal", // 337
		"XcRC4Key", // 338
		"XcRC4Crypt", // 339
		"XcHMAC", // 340
		"XcPKEncPublic", // 341
		"XcPKDecPrivate", // 342
		"XcPKGetKeyLen", // 343
		"XcVerifyPKCS1Signature", // 344
		"XcModExp", // 345
		"XcDESKeyParity", // 346
		"XcKeyTable", // 347
		"XcBlockCrypt", // 348
		"XcBlockCryptCBC", // 349
		"XcCryptService", // 350
		"XcUpdateCrypto", // 351
		"RtlRip", // 352
		"XboxLANKey", // 353
		"XboxAlternateSignatureKeys", // 354
		"XePublicKeyData", // 355
		"HalBootSMCVideoMode", // 356
		"IdexChannelObject", // 357
		"HalIsResetOrShutdownPending", // 358
		"IoMarkIrpMustComplete", // 359
		"HalInitiateShutdown", // 360
		"RtlSnprintf", // 361
		"RtlSprintf", // 362
		"RtlVsnprintf", // 363
		"RtlVsprintf", // 364
		"HalEnableSecureTrayEject", // 365
		"HalWriteSMCScratchRegister", // 366
		"", // 367
		"", // 368
		"", // 369
		"XProfpControl", // 370
		"XProfpGetData", // 371
		"IrtClientInitFast", // 372
		"IrtSweep", // 373
		"MmDbgAllocateMemory", // 374
		"MmDbgFreeMemory", // 375
		"MmDbgQueryAvailablePages", // 376
		"MmDbgReleaseAddress", // 377
		"MmDbgWriteCheck" // 378
	};

	private static final long XBE_EP_RETAIL = 0xA8FC57AB;
	private static final long XBE_EP_DEBUG = 0x94859D4B;
	private static final long XBE_EP_CHIHIRO = 0x40B5C16E;

	private static final long XBE_KP_RETAIL = 0x5B6D40B6;
	private static final long XBE_KP_DEBUG = 0xEFB1F152;
	private static final long XBE_KP_CHIHIRO = 0x2290059D;

	@Override
	public String getName() {
		return "Xbox Executable (XBE)";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		final byte[] expected_magic = { 0x58, 0x42, 0x45, 0x48 };

		// Do not provide a LoadSpec if this isn't an XBE file
		byte[] magic = provider.readBytes(0, 4);
		if (!Arrays.equals(magic, expected_magic)) {
			return loadSpecs;
		}

		// Add a working LoadSpec, assuming XDK made XBEs
		long imageBase = 0x10000;
		LanguageCompilerSpecPair lcs =
			new LanguageCompilerSpecPair("x86:LE:32:default", "windows");
		loadSpecs.add(new LoadSpec(this, imageBase, lcs, true));

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		if (monitor.isCancelled()) {
			return;
		}

		BinaryReader reader = new BinaryReader(provider, true);

		long entry = reader.readUnsignedInt(0x128); //FIXME: xbeHeader.getAddressOfEntryPoint();
		Msg.info(this, "Raw entry point is " + entry);
		long thunk = reader.readUnsignedInt(0x158); //FIXME: Access through xbeHeader
		Msg.info(this, "Raw kernel thunk is " + thunk);

		long entry_key;
		long thunk_key;
		if ((entry & 0xF0000000) == 0x40000000) {
			// Sega Chihiro XBE
			entry_key = XBE_EP_CHIHIRO;
			thunk_key = XBE_KP_CHIHIRO;
		} else if ((entry ^ XBE_EP_RETAIL) > 0x1000000) {
			// Debug XBE
			entry_key = XBE_EP_DEBUG;
			thunk_key = XBE_KP_DEBUG;
		} else {
			// Retail XBE
			entry_key = XBE_EP_RETAIL;
			thunk_key = XBE_KP_RETAIL;
		}

		// Unscramble
		entry = (entry ^ entry_key) & NumberUtil.UNSIGNED_INT_MASK;
		thunk = (thunk ^ thunk_key) & NumberUtil.UNSIGNED_INT_MASK;
		Msg.info(this, "Actual entry point is " + entry);
		Msg.info(this, "Actual kernel thunk is " + thunk);

		// Load headers
		long sizeOfHeaders = reader.readUnsignedInt(0x108); //FIXME: Access through xbeHeader
		//FIXME: Check if there's a round-up / align function
		//FIXME: Get proper image base
		//FIXME: Warn if image base is bad
		//FIXME: Assert that image base is page aligned
		AddSection("Headers", 0x0, sizeOfHeaders, 0x10000, (sizeOfHeaders + 0xFFF) & ~0xFFF, true, false, false, provider, program, handler, monitor, log);

		//FIXME: Mark certificate header
		//FIXME: Mark library versions
		//FIXME: Mark TLS header
		//FIXME: Mark MS logo

		// Load sections
		long sectionCount = reader.readUnsignedInt(0x11C); //FIXME: get from xbeHeader
		long sectionHeaderAddress = reader.readUnsignedInt(0x120); //FIXME: get from xbeHeader

		//FIXME: Instead use already mapped memory; how?
		//sectionHeaderAddress -= 0x10000;

		ByteProvider memoryProvider = new MemoryByteProvider(program.getMemory(),
			program.getAddressFactory().getDefaultAddressSpace());
		BinaryReader memoryReader = new BinaryReader(memoryProvider, true);

		for(int sectionIndex = 0; sectionIndex < sectionCount; sectionIndex++) {
			long flags = memoryReader.readUnsignedInt(sectionHeaderAddress + 0x0);
			long virtualAddress = memoryReader.readUnsignedInt(sectionHeaderAddress + 0x4);
			//FIXME: Round down virtual address
			long virtualSize = memoryReader.readUnsignedInt(sectionHeaderAddress + 0x8);
			//FIXME: Round up virtual size
			long rawAddress = memoryReader.readUnsignedInt(sectionHeaderAddress + 0xC);
			long rawSize = memoryReader.readUnsignedInt(sectionHeaderAddress + 0x10);
			long nameAddress = memoryReader.readUnsignedInt(sectionHeaderAddress + 0x14);
			String name = memoryReader.readAsciiString(nameAddress);
			boolean r = true;
			boolean w = (flags & 0x00000001) != 0;
			boolean x = (flags & 0x00000004) != 0;
			//FIXME: Add other fields somehow?
			AddSection(name, rawAddress, rawSize, virtualAddress, virtualSize, r, w, x, provider, program, handler, monitor, log);
			sectionHeaderAddress += 0x38;
		}

		if (thunk != 0) {
			processKernelThunk(thunk, memoryProvider, program, handler, monitor, log);
		}
		processEntryPoint(entry, program, monitor);

		monitor.setMessage(program.getName() + ": done!");
	}

	//FIXME: Stolen from PeLoader.java
	/**
	 * Mark this location as code in the CodeMap.
	 * The analyzers will pick this up and disassemble the code.
	 *
	 * TODO: this should be in a common place, so all importers can communicate that something
	 * is code or data.
	 *
	 * @param program The program to mark up.
	 * @param address The location.
	 */
	private void markAsCode(Program program, Address address) {
		AddressSetPropertyMap codeProp = program.getAddressSetPropertyMap("CodeMap");
		if (codeProp == null) {
			try {
				codeProp = program.createAddressSetPropertyMap("CodeMap");
			}
			catch (DuplicateNameException e) {
				codeProp = program.getAddressSetPropertyMap("CodeMap");
			}
		}

		if (codeProp != null) {
			codeProp.add(address, address);
		}
	}

	private void AddSection(String name, long rawAddress, long rawSize, long virtualAddress, long virtualSize, boolean r, boolean w, boolean x, ByteProvider provider, Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {

		if (monitor.isCancelled()) {
			return;
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		MemoryBlockUtil mbu = new MemoryBlockUtil(program, handler);
		try {
			try {
				Address address = space.getAddress(virtualAddress);
				try (InputStream dataStream = provider.getInputStream(rawAddress)) {
					mbu.createInitializedBlock(name, address, dataStream, virtualSize, "", "", r, w,
						x, monitor);
				}
			}
			finally {
				log.appendMsg(mbu.getMessages());
				mbu.dispose();
				mbu = null;
			}
		}
		catch (AddressOverflowException e) {
			throw new IOException(e);
		}
	}

	private void processKernelThunk(long thunk, ByteProvider memoryProvider, Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage(program.getName() + ": processing kernel thunk...");

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		SymbolTable symTable = program.getSymbolTable();

		//HACK: Add a kernel stub (only works for functions, not variables)
		//FIXME: Find a better solution
		MemoryBlockUtil mbu = new MemoryBlockUtil(program, handler);
		try {
			Address address = space.getAddress(0x80000000);
			mbu.createUninitializedBlock(false, "xboxkrnl_stub", address, kernelExportNames.length, "", "", true, false, true);
		}
		finally {
			log.appendMsg(mbu.getMessages());
			mbu.dispose();
			mbu = null;
		}

		//HACK: Place label at those addresses
		for(int stubIndex = 0; stubIndex < kernelExportNames.length; stubIndex++) {
			Address address = space.getAddress(0x80000000 + stubIndex);
			try {
				// Add label
				symTable.createLabel(address, kernelExportNames[stubIndex], SourceType.IMPORTED);

				// Mark as code
				//FIXME: is this necessary?
				markAsCode(program, address);

				// Turn this into a 1-byte function
				Function function = null;
				try {
					FunctionManager functionMgr = program.getFunctionManager();
					function = functionMgr.getFunctionAt(address);
					if (function == null) {
						function = functionMgr.createFunction(null, address, new AddressSet(address),
							SourceType.IMPORTED);
					}
				}
				catch (Exception e) {
					// ignore
				}
			}
			catch (InvalidInputException e) {
				// ignore
			}
		}

		BinaryReader memoryReader = new BinaryReader(memoryProvider, true);

		while(!monitor.isCancelled()) {

			// Read thunk and leave if it's a null-pointer (marks end of table)
			long thunkValue = memoryReader.readUnsignedInt(thunk);
			if (thunkValue == 0) {
				break;
			}

			// Extract the kernel export ordinal
			//FIXME: assert thunkvalue & 0x80000000
			int ordinal = (int)thunkValue & 0x1FF;
			long addr = thunk;

			//FIXME: assert ordinal is lower than kernel export count

			//FIXME: Add reference to function or something?

			// Go to next thunk
			thunk += 4;
		}
	}

	private void processEntryPoint(long entry, Program program, TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			return;
		}
		monitor.setMessage(program.getName() + ": processing entry point...");

		AddressFactory af = program.getAddressFactory();
		AddressSpace space = af.getDefaultAddressSpace();
		SymbolTable symTable = program.getSymbolTable();

		Address entryAddr = space.getAddress(entry);
		try {
			symTable.createLabel(entryAddr, "entry", SourceType.IMPORTED);
			markAsCode(program, entryAddr);
		}
		catch (InvalidInputException e) {
			// ignore
		}
		symTable.addExternalEntryPoint(entryAddr);
	}
}
