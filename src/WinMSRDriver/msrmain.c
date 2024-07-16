// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2009-2022, Intel Corporation

/*

   WARNING: This driver code is only for testing purposes, not for production use
*/

#include "msr.h"
#include "ntdef.h"
#include <wdm.h>


/*!     \file msrmain.cpp
        \brief Test Windows 7 Model Specific Driver implementation
*/

#define NT_DEVICE_NAME L"\\Driver\\RDMSR"
#define DOS_DEVICE_NAME L"\\DosDevices\\RDMSR"
#define MSR_MAX_CPU_COUNT (2048)
// pcm IOCTL -> MSR lock state -> MSR KeInsertQueueDpc -> MSR WaitFor dpcDone -> MSR unlock state -> ... -> pcm IOCTL done
typedef struct _DPC_CONTEXT
{
    enum WHAT_TO_DO {
        RDMSR,
        WRMSR,
    } whatToDo;
    ULONG64 readData;
    KEVENT  dpcDoneEvent;
    ULONG success;
} DPC_CONTEXT, *PDPC_CONTEXT;

typedef struct _PER_PROCESSOR_DPC_STATE
{
    __declspec(align(8))
    FAST_MUTEX mutex;
    KDPC       dpc;
    DPC_CONTEXT dpcContext;
} PER_PROCESSOR_DPC_STATE, *PPER_PROCESSOR_DPC_STATE;

struct DeviceExtension
{
    HANDLE devMemHandle;
    HANDLE counterSetHandle;
    ULONG processorCount;
    PER_PROCESSOR_DPC_STATE PerProcDpcState[MSR_MAX_CPU_COUNT];
};

DRIVER_INITIALIZE DriverEntry;

__drv_dispatchType(IRP_MJ_CREATE)
__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH dummyFunction;

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH deviceControl;

DRIVER_UNLOAD MSRUnload;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT,DriverEntry)
#pragma alloc_text(PAGE,MSRUnload)
#pragma alloc_text(PAGE,dummyFunction)
#pragma alloc_text(PAGE,deviceControl)
#endif

void
MyDeferredRoutine(
    KDPC* Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(Dpc);
    PDPC_CONTEXT ctx = (PDPC_CONTEXT)DeferredContext;
    ctx->success = 0;
    switch(ctx->whatToDo)
    {
    case RDMSR:
        __try
        {
            ctx->readData = __readmsr(SystemArgument1);
            ctx->success = 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ctx->readData = 0;
        }        
        break;
    case WRMSR:
        __try
        {
            __writemsr(SystemArgument1, SystemArgument2);
            ctx->success = 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ctx->readData = 0;
        }
        break;
    default:
        // How do you get in here?
        // __debugbreak();
        break;
    }
    KeSetEvent(&ctx->dpcDoneEvent, 0, FALSE);
}

NTSTATUS
DriverEntry(
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING UnicodeString;
    UNICODE_STRING dosDeviceName;
    PDEVICE_OBJECT MSRSystemDeviceObject = NULL;
    struct DeviceExtension * pExt = NULL;
    UNICODE_STRING devMemPath;
    OBJECT_ATTRIBUTES attr;
    ULONG processorCount;
    ULONG i;
    PPER_PROCESSOR_DPC_STATE dpcState;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&UnicodeString, NT_DEVICE_NAME);
    RtlInitUnicodeString(&dosDeviceName, DOS_DEVICE_NAME);

    status = IoCreateDevice(DriverObject,
                            sizeof(struct DeviceExtension),
                            &UnicodeString,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &MSRSystemDeviceObject
                            );

    if (!NT_SUCCESS(status))
        return status;

    DriverObject->DriverUnload = MSRUnload;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = dummyFunction;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = dummyFunction;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = deviceControl;

    pExt = DriverObject->DeviceObject->DeviceExtension;
    processorCount = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (MSR_MAX_CPU_COUNT < processorCount)
    {
        // How did you get this much CPU? You must be from Wall street, go fix the macro
        return STATUS_UNSUCCESSFUL;
    }

    for (i = 0; i < processorCount; ++i)
    {
        dpcState = &pExt->PerProcDpcState[i];

        ExInitializeFastMutex(&dpcState->mutex);
        KeInitializeEvent(&dpcState->dpcContext.dpcDoneEvent, SynchronizationEvent, FALSE);
    }
    pExt->processorCount = processorCount;
    
    RtlInitUnicodeString(&devMemPath, L"\\Device\\PhysicalMemory");
    InitializeObjectAttributes(&attr, &devMemPath, OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
    status = ZwOpenSection(&pExt->devMemHandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &attr);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Error: failed ZwOpenSection(devMemHandle) => %08X\n", status);
        return status;
    }
    pExt->counterSetHandle = NULL;

    IoCreateSymbolicLink(&dosDeviceName, &UnicodeString);

    return status;
}


NTSTATUS dummyFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;


    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


VOID MSRUnload(PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING nameString;

    PAGED_CODE();

    RtlInitUnicodeString(&nameString, DOS_DEVICE_NAME);
        IoDeleteSymbolicLink(&nameString);


    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }
}

int isGoodBuffer(PVOID buffer, SIZE_T size, int try_write)
{
    int good = 0;
    ULONG_PTR page_address;
    SIZE_T page_count;
    volatile char v;

    if (NULL != buffer && 0 != size)
    {
        __try
        {
            ProbeForRead(buffer, size, 1);
            page_address = (ULONG_PTR)PAGE_ALIGN(buffer);
            page_count = BYTES_TO_PAGES(size);
            while (page_count--)
            {
                if (try_write)
                {
                    *(volatile char*)(page_address) = 0x00;
                }
                else
                {
                    v = *(volatile char*)(page_address);
                }
                page_address += PAGE_SIZE;
            }
            good = 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return good;
}

NTSTATUS deviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStackLocation = NULL;
    struct MSR_Request * input_msr_req = NULL;
    struct PCICFG_Request * input_pcicfg_req = NULL;
    struct MMAP_Request* input_mmap_req = NULL;
    ULONG64 * output = NULL, *input = NULL;
    ULONG inputSize = 0, outputSize = 0;
    PCI_SLOT_NUMBER slot;
    unsigned size = 0;
    PROCESSOR_NUMBER ProcNumber;
    struct DeviceExtension* pExt = NULL;
    LARGE_INTEGER offset;
    SIZE_T mmapSize = 0;
    PVOID baseAddress = NULL;
    PPER_PROCESSOR_DPC_STATE dpcState;
    enum WHAT_TO_DO what = RDMSR;

    pExt = DeviceObject->DeviceExtension;

    PAGED_CODE();

    IrpStackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (IrpStackLocation)
    {
        input = IrpStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
        inputSize = IrpStackLocation->Parameters.DeviceIoControl.InputBufferLength;
        output = (ULONG64*)Irp->UserBuffer;
        outputSize = IrpStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

        if (outputSize >= sizeof(ULONG64)
            && isGoodBuffer(input, inputSize, 0)
            && isGoodBuffer(output, outputSize, 1))
        {
            input_msr_req = (struct MSR_Request *)input;
            input_pcicfg_req = (struct PCICFG_Request *)input;
            input_mmap_req = (struct MMAP_Request*)input;

            RtlSecureZeroMemory(&ProcNumber, sizeof(PROCESSOR_NUMBER));

            switch (IrpStackLocation->Parameters.DeviceIoControl.IoControlCode)
            {
            case IO_CTL_MSR_WRITE:
                what = WRMSR;
            case IO_CTL_MSR_READ:
                if (inputSize < sizeof(struct MSR_Request)
                    || !(0 <= input_msr_req->core_id && input_msr_req->core_id < (int)pExt->processorCount)
                    )
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                dpcState = &pExt->PerProcDpcState[input_msr_req->core_id];
                
                ExAcquireFastMutex(&dpcState->mutex);

                dpcState->dpcContext.whatToDo = what;

                KeInitializeDpc(&dpcState->dpc, MyDeferredRoutine, &dpcState->dpcContext);
                RtlSecureZeroMemory(&ProcNumber, sizeof(PROCESSOR_NUMBER));
                KeGetProcessorNumberFromIndex(input_msr_req->core_id, &ProcNumber);
                status = KeSetTargetProcessorDpcEx(&dpcState->dpc, &ProcNumber);
                if (NT_SUCCESS(status))
                {
                    KeSetImportanceDpc(&dpcState->dpc, HighImportance);
                    if (KeInsertQueueDpc(&dpcState->dpc, (PVOID)input_msr_req->msr_address, (PVOID)input_msr_req->write_value))
                    {
                        status = KeWaitForSingleObject(&dpcState->dpcContext.dpcDoneEvent, Executive, KernelMode, FALSE, NULL);
                        if (dpcState->dpcContext.success)
                        {
                            if (RDMSR == what)
                            {
                                *output = dpcState->dpcContext.readData;
                            }
                        }
                        else
                        {
                            status = STATUS_UNSUCCESSFUL;
                        }                        
                    }
                    else
                    {
                        status = STATUS_UNSUCCESSFUL;
                        DbgPrint("Error: Failed to queue dpc in IO_CTL_MSR_WRITE core 0x%X msr 0x%llX value 0x%llX\n",
                            input_msr_req->core_id, input_msr_req->msr_address, input_msr_req->write_value);
                    }
                }
                ExReleaseFastMutex(&dpcState->mutex);
                Irp->IoStatus.Information = (RDMSR == what)? sizeof(ULONG64): 0; // result size
                break;
            case IO_CTL_MMAP_SUPPORT:
                *output = 1;
                Irp->IoStatus.Information = sizeof(ULONG64); // result size
                break;
            case IO_CTL_MMAP:
                offset = input_mmap_req->address;
                mmapSize = input_mmap_req->size;
                status = ZwMapViewOfSection(pExt->devMemHandle, ZwCurrentProcess(), &baseAddress, 0L, PAGE_SIZE, &offset, &mmapSize, ViewUnmap, 0, PAGE_READWRITE);
                if (status != STATUS_SUCCESS || baseAddress == NULL)
                {
                    DbgPrint("Error: ZwMapViewOfSection failed, %lld %lld (%ld).\n", offset.QuadPart, mmapSize, status);
                }
                else
                {
                    *output = (ULONG64)baseAddress;
                    Irp->IoStatus.Information = sizeof(PVOID); // result size
                }
                break;
            case IO_CTL_MUNMAP:
                status = ZwUnmapViewOfSection(ZwCurrentProcess(), (PVOID) input_mmap_req->address.QuadPart);
                break;
            case IO_CTL_PMU_ALLOC_SUPPORT:
                *output = 1;
                Irp->IoStatus.Information = sizeof(ULONG64); // result size
                break;
            case IO_CTL_PMU_ALLOC:
                if (pExt->counterSetHandle == NULL)
                {
                    status = HalAllocateHardwareCounters(NULL, 0, NULL, &(pExt->counterSetHandle));
                }
                *output = status;
                Irp->IoStatus.Information = sizeof(ULONG64); // result size
                break;
            case IO_CTL_PMU_FREE:
                if (pExt->counterSetHandle != NULL)
                {
                    status = HalFreeHardwareCounters(pExt->counterSetHandle);
                    if (status == STATUS_SUCCESS)
                    {
                        pExt->counterSetHandle = NULL;
                    }
                }
                *output = status;
                Irp->IoStatus.Information = sizeof(ULONG64); // result size
                break;
            case IO_CTL_PCICFG_WRITE:
                if (inputSize < sizeof(struct PCICFG_Request) || (input_pcicfg_req->bytes != 4 && input_pcicfg_req->bytes != 8))
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                slot.u.AsULONG = 0;
                slot.u.bits.DeviceNumber = input_pcicfg_req->dev;
                slot.u.bits.FunctionNumber = input_pcicfg_req->func;
#pragma warning(push)
#pragma warning(disable: 4996)
                __try
                {
                    size = HalSetBusDataByOffset(PCIConfiguration, input_pcicfg_req->bus, slot.u.AsULONG,
                        &(input_pcicfg_req->write_value), input_pcicfg_req->reg, input_pcicfg_req->bytes);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    size = 0;
                    DbgPrint("Error: exception with code 0x%X in IO_CTL_PCICFG_WRITE b 0x%X d 0x%X f 0x%X reg 0x%X bytes 0x%X value 0x%llX\n",
                        status, input_pcicfg_req->bus, input_pcicfg_req->dev, input_pcicfg_req->func, input_pcicfg_req->reg, input_pcicfg_req->bytes,
                        input_pcicfg_req->write_value);
                }
#pragma warning(pop)
                if (size != input_pcicfg_req->bytes)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                Irp->IoStatus.Information = 0;                                         // result size
                break;
            case IO_CTL_PCICFG_READ:
                if (inputSize < sizeof(struct PCICFG_Request) || (input_pcicfg_req->bytes != 4 && input_pcicfg_req->bytes != 8))
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                slot.u.AsULONG = 0;
                slot.u.bits.DeviceNumber = input_pcicfg_req->dev;
                slot.u.bits.FunctionNumber = input_pcicfg_req->func;
#pragma warning(push)
#pragma warning(disable: 4996)
                __try
                {
                    size = HalGetBusDataByOffset(PCIConfiguration, input_pcicfg_req->bus, slot.u.AsULONG,
                        output, input_pcicfg_req->reg, input_pcicfg_req->bytes);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    status = GetExceptionCode();
                    size = 0;
                    DbgPrint("Error: exception with code 0x%X in IO_CTL_PCICFG_READ b 0x%X d 0x%X f 0x%X reg 0x%X bytes 0x%X\n",
                        status, input_pcicfg_req->bus, input_pcicfg_req->dev, input_pcicfg_req->func, input_pcicfg_req->reg, input_pcicfg_req->bytes);
                }
#pragma warning(pop)
                if (size != input_pcicfg_req->bytes)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                Irp->IoStatus.Information = size;                                         // result size
                break;

            default:
                status = STATUS_INVALID_DEVICE_REQUEST;
            }
        }
        else
            status = STATUS_INVALID_PARAMETER;
    }
    else
        status = STATUS_INVALID_DEVICE_REQUEST;


    Irp->IoStatus.Status = status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}
