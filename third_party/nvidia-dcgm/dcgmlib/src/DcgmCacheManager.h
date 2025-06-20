/*
 * Copyright (c) 2025, NVIDIA CORPORATION.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include "DcgmDiscovery.h"
#include "DcgmFvBuffer.h"
#include "DcgmGpmManager.hpp"
#include "DcgmGpuInstance.h"
#include "DcgmInjectionNvmlManager.h"
#include "DcgmKmsgReader.h"
#include "DcgmMigManager.h"
#include "DcgmMutex.h"
#include "DcgmSettings.h"
#include "DcgmTopology.hpp"
#include "DcgmWatchTable.h"
#include "DcgmWatcher.h"
#include "dcgm_fields.h"
#include "dcgm_fields_internal.hpp"
#include "dcgm_structs.h"
#include "hashtable.h"
#include "timelib.h"
#include "timeseries.h"

#include <DcgmTaskRunner.h>

#include <bitset>
#include <condition_variable>
#include <dcgm_nvml.h>
#include <map>
#include <set>
#include <string>
#include <unordered_map>

/*****************************************************************************/
/* Enum of Bandwidth direction types (ALL, TX, RX) */
typedef enum
{
    DcgmcmDirectionAll = 0,
    DcgmcmDirectionTx,
    DcgmcmDirectionRx
} DcgmcmDirection_t;

/* Summary information types */
typedef enum
{
    DcgmcmSummaryTypeMinimum = 0, /* Minimum value */
    DcgmcmSummaryTypeMaximum,     /* Maximum value */
    DcgmcmSummaryTypeAverage,     /* Simple Average (sum / Nelem) */
    DcgmcmSummaryTypeSum,         /* Sum of the values */
    DcgmcmSummaryTypeCount,       /* Count of the number of values */
    DcgmcmSummaryTypeIntegral,    /* Integral of the values (area under values) */
    DcgmcmSummaryTypeDifference,  /* Difference between the first and last
                                       non-blank value (last - first) */

    DcgmcmSummaryTypeSize /* Always last entry */
} DcgmcmSummaryType_t;

/*****************************************************************************/
typedef struct dcgmcm_sample_t /* This is made to look similar to timeseries_value_t
                                  since that is the underlying data anyway */
{
    timelib64_t timestamp; /* Value timestamp in usec since 1970 */

    union
    {
        double d;      /* Double value */
        long long i64; /* Int 64 value */
        char *str;     /* Null-terminated pointer to allocated memory for strings
                          must be freed if populated */
        void *blob;    /* Allocated memory for blob types. Must be freed if
                          populated */
    } val;

    union
    {
        double d;          /* Double value */
        long long i64;     /* Int 64 value */
        long long ptrSize; /* Size of allocated memory if str or blob is populated.
                              Includes null terminator for str type */
    } val2;                /* Possible second value. This should only be used for string and
               blob types to contain the size of the memory str/blob points at */

} dcgmcm_sample_t, *dcgmcm_sample_p;

/*****************************************************************************/
/* Details for a single watcher of a field. Each fieldId has a vector of these */
typedef struct dcgm_watch_watcher_info_t
{
    DcgmWatcher watcher;             /* Who owns this watch? */
    timelib64_t monitorIntervalUsec; /* How often this field should be sampled */
    timelib64_t maxAgeUsec;          /* Maximum time to cache samples of this
                                          field. If 0, the class default is used */
    int isSubscribed;                /* Does this watcher want live updates
                                          when this field value updates? */
} dcgm_watch_watcher_info_t, *dcgm_watch_watcher_info_p;

/*****************************************************************************/
/*
 * Struct to hold a single watch and its field values
 *
 * IMPORTANT: If you add fields to this struct, update AllocWatchInfo() to
 *            initialize those fields properly. Because we are allocating the
 *            struct with new() and the struct has classes (watchers), we can't
 *            simply memset the struct to zero
 */
typedef struct dcgmcm_watch_info_t
{
    dcgm_entity_key_t watchKey;                      /* Key information for this watch */
    short isWatched;                                 /* Is this field being watched. 1=yes. 0=no */
    short hasSubscribedWatchers;                     /* Does this field have any watchers that
                                           have subscribed for notifications?. This
                                           should be the logical OR of
                                           watchers[0-n].isSubscribed */
    bool pushedByModule;                             /* Are the samples for this watch pushed by another module
                                                        calling AppendSamples()? If so, we won't update it in
                                                        the cache manager's update loop */
    nvmlReturn_t lastStatus;                         /* Last status returned from querying this
                                           value. See NVML_? values in nvml.h */
    timelib64_t lastQueriedUsec;                     /* Last time we updated this value. Used for
                                           determining if we should request an update
                                           of this field or not */
    timelib64_t monitorIntervalUsec;                 /* How often this field should be sampled */
    timelib64_t maxAgeUsec;                          /* Maximum time to cache samples of this
                                           field. If 0, the class default is used */
    timelib64_t execTimeUsec;                        /* Cumulative time spent updating this
                                           field since the cache manager started */
    long long fetchCount;                            /* Number of times that this field has been
                                           fetched from the driver */
    timeseries_p timeSeries;                         /* Time-series of values for this watch */
    std::vector<dcgm_watch_watcher_info_t> watchers; /* Info for each watcher of this
                                                       field. monitorIntervalUsec and
                                                       maxAgeUsec come from this array */
    /* The two fields will only potentially be different for GPU instances and compute instances.
       In many cases, the data is only obtainable at the GPU level for now, and these fields note
       where the data should be polled */
    dcgm_field_entity_group_t practicalEntityGroupId; /* the entity group id where data should
                                                        be polled */
    dcgm_field_eid_t practicalEntityId;               /* the entity id where data should be pulled */
} dcgmcm_watch_info_t, *dcgmcm_watch_info_p;

/*****************************************************************************/
typedef struct dcgmcm_vgpu_info_t
{
    nvmlVgpuInstance_t vgpuId;       /* vGPU Instance ID */
    bool found;                      /* Flag to denote that the vGPU instance is
                                           still active */
    struct dcgmcm_vgpu_info_t *next; /* Pointer to the next node in the list */
} dcgmcm_vgpu_info_t, *dcgmcm_vgpu_info_p;

extern const unsigned int DCGM_BLANK_ENTITY_ID;

/*****************************************************************************/
typedef struct dcgmcm_gpu_info_t
{
    dcgmcm_gpu_info_t()
    {
        gpuId      = 0;
        status     = DcgmEntityStatusUnknown;
        nvmlIndex  = 0;
        nvmlDevice = nullptr;
        memset(uuid, 0, sizeof(uuid));
        brand = DCGM_GPU_BRAND_UNKNOWN;
        memset(&pciInfo, 0, sizeof(pciInfo));
        arch               = DCGM_CHIP_ARCH_UNKNOWN;
        virtualizationMode = DCGM_GPU_VIRTUALIZATION_MODE_NONE;
        memset(&vgpuList, 0, sizeof(vgpuList));
        memset(nvLinkLinkState, DcgmNvLinkLinkStateNotSupported, sizeof(nvLinkLinkState));
        numNvLinks = 0;
    }

    dcgmcm_gpu_info_t(dcgmcm_gpu_info_t const &other)
        : gpuId(other.gpuId)
        , status(other.status)
        , nvmlIndex(other.nvmlIndex)
        , nvmlDevice(other.nvmlDevice)
        , brand(other.brand)
        , arch(other.arch)
        , virtualizationMode(other.virtualizationMode)
        , migEnabled(false)
        , ccMode(0)
        , maxGpcs(other.maxGpcs)
        , usedGpcs(other.usedGpcs)
        , instances(other.instances)
        , ciCount(other.ciCount)
    {
        memcpy(uuid, other.uuid, sizeof(uuid));
        memcpy(&pciInfo, &other.pciInfo, sizeof(pciInfo));
        memcpy(&vgpuList, &other.vgpuList, sizeof(vgpuList));
        memcpy(nvLinkLinkState, other.nvLinkLinkState, sizeof(nvLinkLinkState));
    }

    dcgmcm_gpu_info_t &operator=(dcgmcm_gpu_info_t const &other)
    {
        if (this != &other)
        {
            gpuId              = other.gpuId;
            status             = other.status;
            nvmlIndex          = other.nvmlIndex;
            nvmlDevice         = other.nvmlDevice;
            brand              = other.brand;
            arch               = other.arch;
            virtualizationMode = other.virtualizationMode;
            migEnabled         = other.migEnabled;
            ccMode             = other.ccMode;
            maxGpcs            = other.maxGpcs;
            usedGpcs           = other.usedGpcs;
            numNvLinks         = other.numNvLinks;
            memcpy(uuid, other.uuid, sizeof(uuid));
            memcpy(&pciInfo, &other.pciInfo, sizeof(pciInfo));
            memcpy(&vgpuList, &other.vgpuList, sizeof(vgpuList));
            memcpy(nvLinkLinkState, other.nvLinkLinkState, sizeof(nvLinkLinkState));
            instances = other.instances;
            ciCount   = other.ciCount;
        }
        return *this;
    }

    unsigned int gpuId;        /* ID of this GPU */
    DcgmEntityStatus_t status; /* Status of this GPU */

    /* Cached NVML fields */
    unsigned int nvmlIndex;                         /* NVML index */
    nvmlDevice_t nvmlDevice;                        /* NVML handle. This is currently a static pointer. ok to cache*/
    char uuid[128];                                 /* UUID */
    dcgmGpuBrandType_t brand;                       /* Brand */
    nvmlPciInfo_t pciInfo;                          /* PCI Info */
    dcgmChipArchitecture_t arch;                    /* chip architecture */
    dcgmGpuVirtualizationMode_t virtualizationMode; /* Virtualization mode */
    bool migEnabled       = false;                  /*!< is the device in MIG mode */
    unsigned int ccMode   = 0;                      /* confidential computing mode */
    unsigned int maxGpcs  = 0; /*!< max number of Compute Instances that could be created on the device */
    unsigned int usedGpcs = 0; /*!< Number of actually used GPCs */

    /* vGPU Instance metadata */
    dcgmcm_vgpu_info_p vgpuList; /* Head pointer of the vGPU linked list for this GPU */

    /* NvLink per-lane status */
    dcgmNvLinkLinkState_t nvLinkLinkState[DCGM_NVLINK_MAX_LINKS_PER_GPU];
    unsigned int numNvLinks; // The number of NVLinks on the system according to NVML

    std::vector<DcgmGpuInstance> instances; /* Configured GPU instances */
    unsigned int ciCount = 0;               // Number of compute instances for this GPU

} dcgmcm_gpu_info_t, *dcgmcm_gpu_info_p;

/*****************************************************************************/
/* Version of dcgmcm_gpu_info_t that can be returned to other modules via
   DcgmCacheManager::GetAllGpuInfo */
typedef struct dcgmcm_gpu_info_cached_t
{
    unsigned int gpuId;                             /* ID of this GPU */
    DcgmEntityStatus_t status;                      /* Status of this GPU */
    dcgmGpuBrandType_t brand;                       /* Brand */
    unsigned int nvmlIndex;                         /* NVML index */
    char uuid[128];                                 /* UUID */
    nvmlPciInfo_t pciInfo;                          /* PCI Info */
    dcgmChipArchitecture_t arch;                    /* chip architecture */
    dcgmGpuVirtualizationMode_t virtualizationMode; /* Virtualization mode */
    /* if you add fields to this, make sure they're handled in
       DcgmCacheManager::GetAllGpuInfo */
} dcgmcm_gpu_info_cached_t, *dcgmcm_gpu_info_cached_p;

/*****************************************************************************/
/* Runtime stats for the cache manager */
struct dcgmcm_runtime_stats_t
{
    long long numSleepsSkipped = 0; /* Number of times the cache manager update thread skipped sleeping due
                                   to the update loop taking too long */
    long long numSleepsDone = 0;    /* Number of times the cache manager thread slept for any duration */
    long long sleepTimeUsec = 0;    /* Amount of time the cache manager update thread was sleeping in usec */
    long long awakeTimeUsec = 0;    /* Amount of time the cache manager update thread was awake in usec */

    std::atomic_llong updateCycleFinished = 0; /* Counter of how many update cycles have been finished */
    long long lockCount                   = 0; /* Number of times that the cache manager mutex has been locked. This is
                                              periodically snapshotted from the cache manager update threads */

    dcgmcm_runtime_stats_t() = default;

    dcgmcm_runtime_stats_t(dcgmcm_runtime_stats_t const &other) noexcept
    {
        numSleepsSkipped = other.numSleepsSkipped;
        numSleepsDone    = other.numSleepsDone;
        sleepTimeUsec    = other.sleepTimeUsec;
        awakeTimeUsec    = other.awakeTimeUsec;
        lockCount        = other.lockCount;

        updateCycleFinished.store(other.updateCycleFinished);
    }
    dcgmcm_runtime_stats_t &operator=(dcgmcm_runtime_stats_t const &other) noexcept
    {
        if (this != &other)
        {
            numSleepsSkipped = other.numSleepsSkipped;
            numSleepsDone    = other.numSleepsDone;
            sleepTimeUsec    = other.sleepTimeUsec;
            awakeTimeUsec    = other.awakeTimeUsec;
            lockCount        = other.lockCount;

            updateCycleFinished.store(other.updateCycleFinished);
        }

        return *this;
    }
};

using dcgmcm_runtime_stats_p = dcgmcm_runtime_stats_t *;

/*****************************************************************************/
/* Cache manager update thread context structure. This exists to prevent stack
   overflow in the update thread by storing large objects on the heap */
typedef struct dcgmcm_update_thread_t
{
    dcgmcm_update_thread_t()
        : watchInfo(nullptr)
        , fvBuffer(nullptr)
        , affectedSubscribers(0)
        , m_ownFvBuffer(false)
    {
        memset(&entityKey, 0, sizeof(entityKey));
        memset(numFieldValues, 0, sizeof(numFieldValues));
        memset(fieldValueFields, 0, sizeof(fieldValueFields));
        memset(fieldValueWatchInfo, 0, sizeof(fieldValueWatchInfo));
    }

    /* Information about the entity currently being worked on */
    dcgm_entity_key_t entityKey;   /* Key information for the current entity */
    dcgmcm_watch_info_p watchInfo; /* Optional cached pointer to the watch object for this entity.
                                      If provided, any updates will be cached here */

    DcgmFvBuffer *fvBuffer;           /* If != NULL, this any Append* calls will result in
                                      values being appended to this structure */
    unsigned int affectedSubscribers; /* This is a bitmask of DcgmWatcherType_t bits of which watchers have
                                         suscribed-for updates in fvBuffer. Using a bitmask here to avoid
                                         zeroing a large array of ints every update loop, also not using
                                         a std::set or list of DcgmWatcherType_t's for performance.
                                         Finally, we're not tracking clientId yet. If we ever extend this
                                         functionality to clients, we will have to track client ID as well. */

    int numFieldValues[DCGM_MAX_NUM_DEVICES];                              /* Number of field values per device
                                                                              saved in fieldValueFields and fieldValueWatchInfo*/
    dcgm_field_meta_p fieldValueFields[DCGM_MAX_NUM_DEVICES][NVML_FI_MAX]; /* Fields to update with field-value APIs
                                                                              rather than CacheLatest*Value() */
    dcgmcm_watch_info_p fieldValueWatchInfo[DCGM_MAX_NUM_DEVICES][NVML_FI_MAX]; /* Watch info for field values */

    /*************************************************************************/
    /*
     * Clear a thread context variable so it's ready for next use.
     *
     * This should do as few memsets as possible as this is in the critical path
     * for live field-value processing.
     */
    void Clear()
    {
        /* Clear the field-values counts */
        memset(numFieldValues, 0, sizeof(numFieldValues));
        watchInfo = nullptr;
        if (fvBuffer)
        {
            fvBuffer->Clear();
        }
        affectedSubscribers = 0;
    }

    /*************************************************************************/
    /*
     * Allocate fvBuffer and set the ownFvBuffer flag to indicate that the destructor can safely delete it.
     *
     * In some instances, fvBuffer may be assigned a pre-allocated value or a pointer to a stack object passed
     * through a function argument. To prevent deletion of fvBuffer in these cases, we need to avoid setting the
     * ownFvBuffer flag by not calling initFvBuffer.
     */
    void initFvBuffer()
    {
        fvBuffer      = new DcgmFvBuffer();
        m_ownFvBuffer = true;
    }

    ~dcgmcm_update_thread_t()
    {
        if (m_ownFvBuffer && fvBuffer)
        {
            delete fvBuffer;
        }
    }

private:
    bool m_ownFvBuffer;

} dcgmcm_update_thread_t, *dcgmcm_update_thread_p;

/*****************************************************************************/
/* Callback function
 * Return True if the entry should be used for summary calculation
 * Return False to filter out entry from summary calculation
 */
typedef bool (*pfUseEntryForSummary)(timeseries_entry_p entry, void *userData);

/******************************************************************************
 *
 * This is a callback to provide DcgmCacheManager to be called when a subscribed
 * field value is updated by the cache manager.
 *
 * fvBuffer        IN: Contains buffered field values that have updated that subscribers
 *                     have said they cared about. It's the the callee's job to walk the
 *                     FVs and determine if they need the updates or not.
 * watcherTypes    IN: Which watchers care about the updates in fvBuffer
 * numWatcherTypes IN: How many entries in watcherTypes are valid
 *
 * userData IN: A user-supplied pointer that was passed to
 * DcgmCacheManager::SubscribeForFvUpdates
 */
typedef void (*dcgmOnSubscribedFvUpdate_f)(DcgmFvBuffer *fvBuffer,
                                           DcgmWatcherType_t *watcherTypes,
                                           int numWatcherTypes,
                                           void *userData);

/* Array entry to track each callback that has been registered */
typedef struct
{
    dcgmOnSubscribedFvUpdate_f callback;
    void *userData;
} dcgmSubscribedFvUpdateCBEntry_t;

typedef enum
{
    DcgmcmEventTypeFvUpdate = 0,   // field value update event
    DcgmcmEventTypeMigReconfigure, // Mig reconfigured event

    DcgmcmEventTypeSize // Always last entry
} DcgmcmEventType_t;

typedef void (*dcgmOnMigReconfigure_f)(unsigned int gpuId, void *userData);

typedef struct
{
    DcgmcmEventType_t type; // specifies which kind of subscription this is
    union
    {
        dcgmOnSubscribedFvUpdate_f fvCb; // callback for field value updates
        dcgmOnMigReconfigure_f migCb;    // callback for mig configuration
    } fn;
    void *userData; // user data passed to callback function
} dcgmcmEventSubscription_t;

/*****************************************************************************/
class DcgmCacheManager; /* Forward declare the cache manager so it can be
                           used by DcgmCacheManagerEventThread */

/*****************************************************************************/
/* This class handles reading NVML events like XIDs */
class DcgmCacheManagerEventThread : public DcgmThread
{
private:
    DcgmCacheManager *m_cacheManager; /* Pointer to the cache manager instance
                                         we belong to */

public:
    DcgmCacheManagerEventThread(DcgmCacheManager *cacheManager);
    ~DcgmCacheManagerEventThread(void);

    /*************************************************************************/
    /*
     * Inherited virtual method from DcgmThread. This is the method that
     * actually does the work
     *
     */
    void run(void) override;
};

/*****************************************************************************/
/* Cache manager main class */
class DcgmCacheManager : public DcgmTaskRunner
{
public:
    /* Constructor/destructor */
    DcgmCacheManager();
    ~DcgmCacheManager();

    /*************************************************************************/
    /*
     * Initialize the cache manager, returning errors if they occur on
     * initialization
     *
     * pollInLockStep IN: Whether to poll when told to (1) or at the frequency
     *                    of the most frequent field being watched (0)
     *                    If 1, you will need to force stat collection to occur
     *                    by calling UpdateAllFields()
     * maxSampleAge   IN: Maximum time in seconds to keep a sample within this
     *                    module.
     *
     * Returns 0 on Success
     *        <0 on error
     */
    dcgmReturn_t Init(int pollInLockStep, double maxSampleAge, bool nvmlLoaded);

    /*************************************************************************/
    /*
     * Shutdown and clean up this object, including stopping the monitoring thread
     *
     * Returns 0 on Success
     *        <0 on error
     *
     */
    dcgmReturn_t Shutdown();

    /*************************************************************************/
    /* Empty the contents of the stats cache
     *
     * Returns 0 on success.
     *        <0 on error.
     */
    dcgmReturn_t EmptyCache();

    /*************************************************************************/
    /*
     * Start the the field sampling thread. Call AddFieldWatch for each field
     * you want to be recorded in the cache after this call to enable
     * sampling.
     *
     * Returns: 0 on success
     *         <0 on error
     *
     */
    dcgmReturn_t Start();

    /*************************************************************************/
    /*
     * Subscribe for an event type, like field value updates or mig reconfigurations.
     * updateCB will be called whenever the specified event occurs.
     *
     * eventSub  IN: struct specifying the callback and all relevant information
     *
     */
    dcgmReturn_t SubscribeForEvent(const dcgmcmEventSubscription_t &eventSub);

    /*************************************************************************/
    /*
     * Get info about all of the GPUs the cache manager knows about
     *
     * Returns DCGM_ST_OK on success
     *         Other DCGM_ST_? #define on error
     */
    dcgmReturn_t GetAllGpuInfo(std::vector<dcgmcm_gpu_info_cached_t> &gpuInfo);

    /*************************************************************************/
    /*
     * Are any GPUs in HOST VGPU mode?
     *
     * Returns true if any GPUs are in host VGPU mode
     *         false if not
     */
    bool AreAnyGpusInHostVGPUMode(void);

    /*************************************************************************/
    /*
     * Get the number of GPUs seen by DCGM
     *
     * activeOnly: If set to 1, will not count GPUs that are inaccessible for any
     *             reason. Reasons include (but are not limited to):
     *                 - not on the allowlist
     *                 - being blocked by cgroups
     *                 - fallen off bus
     *
     * Returns: Count of GPUs
     */
    int GetGpuCount(int activeOnly);

    /*************************************************************************/
    /*
     * Get the gpuIds of the GPUs seen by DCGM
     *
     * activeOnly: If set to 1, will not count GPUs that are inaccessible for any
     *             reason. Reasons include (but are not limited to):
     *                 - not on the allowlist
     *                 - being blocked by cgroups
     *                 - fallen off bus
     * gpuIds: Vector of unsigned ints to fill with GPU IDs.
     *
     * Returns: 0 on success
     *          DCGM_ST_? #define on error
     */
    dcgmReturn_t GetGpuIds(int activeOnly, std::vector<unsigned int> &gpuIds);

    /*************************************************************************/
    /*
     * Get profile info and status for the specified GPU
     *
     * gpuId: specific GPU to query
     * profileInfo: information about the various workload power profiles supported by this GPU
     * profileStatus: the status of the various workload power profiles supported by this GPU
     *
     * Returns: 0 on success
     *          DCGM_ST_? #define on error
     */
    dcgmReturn_t GetWorkloadPowerProfilesInfo(unsigned int gpuId,
                                              dcgmWorkloadPowerProfileProfilesInfo_v1 *profilesInfo,
                                              dcgmDeviceWorkloadPowerProfilesStatus_v1 *profilesStatus);

    /*************************************************************************/
    /*
     * Get the entities seen by DCGM of a given entityGroupId
     *
     * activeOnly     IN: If set to 1, will not count GPUs that are inaccessible for any
     *                    reason. Reasons include (but are not limited to):
     *                    - not on the allowlist
     *                    - being blocked by cgroups
     *                    - fallen off bus
     * entityGroupId IN: Which entity group to fetch the entities of
     * entities     OUT: Entity IDs
     *
     * Returns: 0 on success
     *          DCGM_ST_? #define on error
     */

    dcgmReturn_t GetAllEntitiesOfEntityGroup(int activeOnly,
                                             dcgm_field_entity_group_t entityGroupId,
                                             std::vector<dcgmGroupEntityPair_t> &entities);

    /*************************************************************************/
    /*
     * Get the status of an entity
     *
     * entityGroupId is the group the entity belongs to
     * entityId is the ID of the entity
     *
     * Returns a GPU status enum
     *
     */
    DcgmEntityStatus_t GetEntityStatus(dcgm_field_entity_group_t entityGroupId, dcgm_field_eid_t entityId);

    /*************************************************************************/
    /*
     * Get the status of a GPU
     *
     * gpuId is the ID of the GPU to get the status of
     *
     * Returns a GPU status enum
     *
     */
    DcgmEntityStatus_t GetGpuStatus(unsigned int gpuId);

    /*************************************************************************/
    /*
     * Get the brand of a given GPU
     *
     * Returns: DCGM_GPU_BRAND_UNKNOWN if the gpuId is invalid
     *          Otherwise the DCGM_GPU_BRAND_* of the GPU found.
     */
    dcgmGpuBrandType_t GetGpuBrand(unsigned int gpuId);

    /*************************************************************************/
    /*
     * Get the GPU Chip Architecture information
     *
     * gpuId is the ID of the GPU to get the Architecture of
     *
     * Returns: 0 on success
     *          DCGM_ST_? #define on error
     *
     */
    dcgmReturn_t GetGpuArch(unsigned int gpuId, dcgmChipArchitecture_t &arch);

    /*************************************************************************/
    /*
     * Get the list of GPUs that were excluded by the driver
     *
     * Note: This will only work on r400 or newer drivers. Otherwise, an empty
     *       list will always be returned.
     *
     * Returns: 0 on success
     *          DCGM_ST_? #define on error.
     */
    dcgmReturn_t GetGpuExcludeList(std::vector<nvmlExcludedDeviceInfo_t> &excludeList);

    /*************************************************************************/
    /*
     * Inherited virtual method from DcgmThread. This is the method that
     * actually does the work
     *
     */

    void run(void) override;

    /*************************************************************************/
    /*
     * Pause or resume field sampling for a given GPU or all GPUs
     *
     * If pausing, this function blocks until the pause has been confirmed by
     * the sampling loop so that the sampling loop doesn't get unexpected errors
     * and the caller can safely do things like reset the GPU.
     *
     * gpuId    IN: Which GPU to pause/resume on
     *
     * Returns: 0 on success
     *          DCGM_ST_? #define on error.
     *
     *
     */
    dcgmReturn_t PauseGpu(unsigned int gpuId);
    dcgmReturn_t ResumeGpu(unsigned int gpuId);
    dcgmReturn_t Pause();
    dcgmReturn_t Resume();

    /*************************************************************************/
    /*
     * This notifies the sampling thread that
     * it should do a round of sampling before going to sleep again.
     *
     * waitForUpdate IN: Whether (1) or not (0) the caller should wait for the
     *                   triggered update cycle to finish before returning.
     *
     * Returns 0 on success
     *         DCGM_ST_? #define on error.
     *
     */
    dcgmReturn_t UpdateAllFields(int waitForUpdate);


    /*************************************************************************/
    /*
     * Add watching of a field by this class. Samples will be gathered every
     * monitorIntervalUsec usec. Samples will only be kept for a maximum of
     * maxSampleAge seconds before being discarded.
     *
     * If a field is already watched the resulting monitor frequency and
     * maxSampleAge will be the maximum of what is currently set and what is
     * passed in on the new watch
     *
     * entityGroupId        IN: Which entity group this watch pertains to
     * entityId             IN: Which entity ID this watch pertains to
     * dcgmFieldId          IN: Which DCGM field to add the watch for
     * monitorIntervalUsec IN: How often in usec to gather samples for this field.
     *                          0=use default from DcgmField metadata
     * maxSampleAge         IN: How long to keep samples for in seconds.
     *                          0.0 = use default from DcgmField metadata
     * maxKeepSamples       IN: Maximum number of samples to keep.
     *                          0=no limit
     * watcher              IN: Who is watching this field? Used for tracking purposes
     * subscribeForUpdates  IN: Whether watcher wants to receive notification callbacks
     *                          whenever this field value updates
     * updateOnFirstWatch   IN: Whether we should do an UpdateAllFields(true) if we were
     *                          the first watcher or not. Pass true if you want to guarantee
     *                          there is a value in the cache after this call. Pass false if you
     *                          don't care or plan to batch together a bunch of watches before
     *                          an UpdateAllFields() at the end
     * wereFirstWatcher    OUT: Whether we were the first watcher (true) or not (false). If so,
     *                          you will need to call UpdateAllFields(true) for a value to be
     *                          present in the cache.
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     *
     */
    dcgmReturn_t AddFieldWatch(dcgm_field_entity_group_t entityGroupId,
                               dcgm_field_eid_t entityId,
                               unsigned short dcgmFieldId,
                               timelib64_t monitorIntervalUsec,
                               double maxSampleAge,
                               int maxKeepSamples,
                               DcgmWatcher watcher,
                               bool subscribeForUpdates,
                               bool updateOnFirstWatch,
                               bool &wereFirstWatcher);

    /*************************************************************************/
    /*
     * Update the caching frquency, maxSampleAge and maxKeepSamples for a given field
     * into watchInfo.
     *
     * monitorIntervalUsec IN: How often in usec to gather samples for this field.
     *                          0=use default from DcgmField metadata
     * maxSampleAge         IN: How long to keep samples for in seconds.
     *                          0.0 = use default from DcgmField metadata
     * maxKeepSamples       IN: Maximum number of samples to keep.
     *                          0=no limit
     * watcher              IN: Who is watching this field? Used for tracking purposes
     *
     * Returns 0                   on success
     *         DCGM_ST_NOT_WATCHED on field not watched.
     *         DCGM_ST_BADPARAM    on NULL watchInfo.
     *
     */
    dcgmReturn_t UpdateFieldWatch(dcgmcm_watch_info_p watchInfo,
                                  timelib64_t updatedmonitorIntervalUsec,
                                  double maxSampleAge,
                                  int maxKeepSamples,
                                  DcgmWatcher watcher);

    /*************************************************************************/
    /*
     * Stop and remove monitoring of a field for a GPU
     *
     * entityGroupId IN: Which entity group to remove the watch for
     * entityId      IN: Which entity within entityGroupId to remove the watch for
     * dcgmFieldId   IN: Which DCGM field to remove the watch for
     * clearCache    IN: Whether (1) or not (0) to clear cached data after
     *                   we've stopped monitoring data
     * watcher       IN: Who is watching this field? Used for tracking purposes
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     *
     */
    dcgmReturn_t RemoveFieldWatch(dcgm_field_entity_group_t entityGroupId,
                                  dcgm_field_eid_t entityId,
                                  unsigned short dcgmFieldId,
                                  int clearCache,
                                  DcgmWatcher watcher);

    /*************************************************************************/
    /*
     * Get the latest instance of a PID's accounting data from the cache manager
     *
     * gpuId     IN: Which GPU to get the value for
     * pid       IN: Process ID to get accounting data for
     * pidInfo  OUT: Process information for pid. Only valid if this function returns 0
     *
     * Returns: 0 on success
     *         <0 on error. See DCGM_ST_? enums
     *
     */
    dcgmReturn_t GetLatestProcessInfo(unsigned int gpuId, unsigned int pid, dcgmDevicePidAccountingStats_t *pidInfo);

    /*************************************************************************/
    /*
     * Get a list of unique graphics or compute pids
     *
     * entityGroupId   IN: Which entity group this entity belongs to
     * entityId        IN: Which entity to get PIDs for
     * dcgmfieldId     IN: Field ID to get the PID list from. Currently supported fields:
     *                          DCGM_FI_DEV_GRAPHICS_PIDS
     *                          DCGM_FI_DEV_COMPUTE_PIDS
     * excludePid      IN: Optional PID to exclude from the list. 0=no exclusion
     * pids           OUT: PIDs. numPids contains the count
     * numPids         IO: On calling, contains the capacity of pids. The output
     *                     is the number of entries set in pids
     * startTime       IN: Optional starting timestamp. Samples >= this value will
     *                     be returned. 0=Return samples from beginning
     * endTime         IN: Optional ending timestamp. Samples <= this value will
     *                     be returned. 0=Return samples up until end
     *
     * Returns: 0 on success.
     *          DCGM_ST_? enum on error.
     */
    dcgmReturn_t GetUniquePidLists(dcgm_field_entity_group_t entityGroupId,
                                   dcgm_field_eid_t entityId,
                                   unsigned short dcgmFieldId,
                                   unsigned int excludePid,
                                   dcgmProcessUtilInfo_t *pidInfo,
                                   unsigned int *numPids,
                                   timelib64_t startTime,
                                   timelib64_t endTime);

    /*************************************************************************/
    /*
     * Get a list of unique graphics or compute pids
     *
     * entityGroupId   IN: Which entity group this entity belongs to
     * entityId        IN: Which entity to get PIDs for
     * dcgmfieldId     IN: Field ID to get the PID list from. Currently supported fields:
     *                          DCGM_FI_DEV_GRAPHICS_PIDS
     *                          DCGM_FI_DEV_COMPUTE_PIDS
     * excludePid      IN: Optional PID to exclude from the list. 0=no exclusion
     * pids                 OUT: pidInfo, contains PID and the utilization rates.
     * numPids         IO: On calling, contains the capacity of pids. The output
     *                     is the number of entries set in pids
     * startTime       IN: Optional starting timestamp. Samples >= this value will
     *                     be returned. 0=Return samples from beginning
     * endTime         IN: Optional ending timestamp. Samples <= this value will
     *                     be returned. 0=Return samples up until end
     *
     * Returns: 0 on success.
     *          DCGM_ST_? enum on error.
     */
    dcgmReturn_t GetUniquePidLists(dcgm_field_entity_group_t entityGroupId,
                                   dcgm_field_eid_t entityId,
                                   unsigned short dcgmFieldId,
                                   unsigned int excludePid,
                                   unsigned int *pids,
                                   unsigned int *numPids,
                                   timelib64_t startTime,
                                   timelib64_t endTime);


    /*************************************************************************/
    /*
     * Get a list of unique pid utilization entries in the utilization sample.
     *
     * entityGroupId   IN: Which entity group this entity belongs to
     * entityId        IN: Which entity to get process Utilization for
     * dcgmfieldId     IN: Field ID to get the process Utilization from. Currently supported fields:
     *                          DCGM_FI_DEV_GPU_UTIL_SAMPLES
     *                          DCGM_FI_DEV_MEM_COPY_UTIL_SAMPLES
     * includePid      IN: (Optional)If specified, the utilization data
                             for only this PID is being retrieved.
     * processUtilSamples         OUT: Unique PID utilization samples.
     * numUniqueSamples        OUT: Number of Unique pid utilization samples.
     * startTime       IN: Optional starting timestamp. Samples >= this value will
     *                     be returned. 0=Return samples from beginning
     * endTime         IN: Optional ending timestamp. Samples <= this value will
     *                     be returned. 0=Return samples up until end
     *
     * Returns: 0 on success.
     *          DCGM_ST_? enum on error.
     */
    dcgmReturn_t GetUniquePidUtilLists(dcgm_field_entity_group_t entityGroupId,
                                       dcgm_field_eid_t entityId,
                                       unsigned short dcgmFieldId,
                                       unsigned int includePid,
                                       dcgmProcessUtilSample_t *processUtilSamples,
                                       unsigned int *numUniqueSamples,
                                       timelib64_t startTime,
                                       timelib64_t endTime);


    /*************************************************************************/
    /*
     * Get summary information for a set of samples
     *
     * entityGroupId IN: Which entity group to get the value for
     * entityId      IN: The entity to get the value for
     * dcgmFieldId     IN: Which DCGM field to get the summaries for
     * numSummaryTypes IN: Number of entries in summaryTypes[] and summaryValues[]
     * summaryTypes    IN: Types of summary data to request
     * summaryValues  OUT: Summary values at hte same indexes as summaryTypes
     * startTime       IN: Optional starting timestamp. Samples >= this value will
     *                     be returned. 0=Return samples from beginning
     * endTime         IN: Optional ending timestamp. Samples <= this value will
     *                     be returned. 0=Return samples up until end
     * enumCB          IN: Callback to check if the entry should be used for calculation of summary
     * userData        IN: User provided data to be passed to the callback function
     *
     */
    dcgmReturn_t GetInt64SummaryData(dcgm_field_entity_group_t entityGroupId,
                                     dcgm_field_eid_t entityId,
                                     unsigned short dcgmFieldId,
                                     int numSummaryTypes,
                                     DcgmcmSummaryType_t *summaryTypes,
                                     long long *summaryValues,
                                     timelib64_t startTime,
                                     timelib64_t endTime,
                                     pfUseEntryForSummary enumCB,
                                     void *userData);
    dcgmReturn_t GetFp64SummaryData(dcgm_field_entity_group_t entityGroupId,
                                    dcgm_field_eid_t entityId,
                                    unsigned short dcgmFieldId,
                                    int numSummaryTypes,
                                    DcgmcmSummaryType_t *summaryTypes,
                                    double *summaryValues,
                                    timelib64_t startTime,
                                    timelib64_t endTime,
                                    pfUseEntryForSummary enumCB,
                                    void *userData);

    /*************************************************************************/
    /*
     * Get samples of a time series field
     *
     * entityGroupId IN: Which entity group to get the value for
     * entityId      IN: The entity to get the value for
     * dcgmFieldId  IN: Which DCGM field to get the value for
     * samples     OUT: Where to place samples. Capacity of this memory should
     *                  be provided in Msamples. Can be nullptr if fvBuffer is
     *                  provided.
     * Msamples     IO: When called, is the capacity that samples can hold.
     *                  When returning, Msamples contains the number of samples
     *                  actually stored in samples[]
     * sampleType  OUT: Type of samples returned in samples. This is a DCGM_FT_?
     *                  #define and redundant with the DcgmField definition
     * startTime    IN: Optional starting timestamp. Samples >= this value will
     *                  be returned. 0=Return samples from beginning
     * endTime      IN: Optional ending timestamp. Samples <= this value will
     *                  be returned. 0=Return samples up until end
     * order        IN: Which order to walk records in.
     *                  DCGM_ORDER_ASCENDING = increasing timestamps, starting from
     *                       startTime
     *                  DCGM_ORDER_DESCENDING = decreasing timestamps, starting from
     *                       endTime
     * fvBuffer    OUT: Optional fvBuffer to write the samples to. Can be nullptr
     *                  if samples[] is provided
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     */
    dcgmReturn_t GetSamples(dcgm_field_entity_group_t entityGroupId,
                            dcgm_field_eid_t entityId,
                            unsigned short dcgmFieldId,
                            dcgmcm_sample_p samples,
                            int *Msamples,
                            timelib64_t startTime,
                            timelib64_t endTime,
                            dcgmOrder_t order,
                            DcgmFvBuffer *fvBuffer);


    /*************************************************************************/
    /*
     * Get the most recent sample of a field
     *
     * entityGroupId IN: Which entity group to get the value for
     * entityId      IN: The entity to get the value for
     * dcgmFieldId   IN: Which DCGM field to get the value for
     * sample       OUT: Where to place sample (optional)
     * fvBuffer     OUT: Alternative place to place sample (optional)
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     */
    dcgmReturn_t GetLatestSample(dcgm_field_entity_group_t entityGroupId,
                                 dcgm_field_eid_t entityId,
                                 unsigned short dcgmFieldId,
                                 dcgmcm_sample_p sample,
                                 DcgmFvBuffer *fvBuffer);

    /*************************************************************************/
    /*
     * Get the most recent sample of multiple entities for multiple fields into
     * a fvBuffer
     *
     * There is both a cached version and live version of this API
     *
     * entityList    IN: Entities to fetch the latest values for
     * fieldIds      IN: Field IDs to fetch for each entity
     * fvBuffer     OUT: Where to place samples.
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     */
    dcgmReturn_t GetMultipleLatestSamples(std::vector<dcgmGroupEntityPair_t> &entities,
                                          std::vector<unsigned short> &fieldIds,
                                          DcgmFvBuffer *fvBuffer);
    dcgmReturn_t GetMultipleLatestLiveSamples(std::vector<dcgmGroupEntityPair_t> &entities,
                                              std::vector<unsigned short> &fieldIds,
                                              DcgmFvBuffer *fvBuffer);

    /*************************************************************************/
    /*
     * Set value for a field
     *
     * gpuId        IN: Which GPU to get the value for
     * dcgmFieldId  IN: Which DCGM field to get the value for
     * value        IN: Value to be set
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     */
    dcgmReturn_t SetValue(int gpuId, unsigned short dcgmFieldId, dcgmcm_sample_p value);

    /*****************************************************************************/
    /*
     * AppendSamples is called from Fabric Manager to add switch statistics and
     * error notifications. It is implemented as a separate method from
     * InjectSamples, in case the two functionalities need to diverge in future.
     * For now, AppendSamples just invokes InjectSamples.
     *
     * entityGroupId IN: Which entity group to inject the value for
     * entityId      IN: ID of the entity to inject (GPU ID for GPUs)
     * dcgmFieldId   IN: Which DCGM field to inject the value for
     * samples       IN: Array of samples to inject
     * Nsamples      IN: Number of samples that are contained in samples[]
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     *
     */
    dcgmReturn_t AppendSamples(dcgm_field_entity_group_t entityGroupId,
                               dcgm_field_eid_t entityId,
                               unsigned short dcgmFieldId,
                               dcgmcm_sample_p samples,
                               int Nsamples);

    /*****************************************************************************/
    /*
     * AppendSamples is called from DCGM modules to batch-publish metrics into
     * the cache manager.
     *
     * fvBuffer IN: Buffer of samples to publish into the cache manager. This remains
     *              owned by the caller after this call.
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     *
     */
    dcgmReturn_t AppendSamples(DcgmFvBuffer *fvBuffer);

    /*************************************************************************/
    /*
     * Inject fake value(s) for a GPU for a field into the cache manager
     *
     * entityGroupId IN: Which entity group to inject the value for
     * entityId      IN: ID of the entity to inject (GPU ID for GPUs)
     * dcgmFieldId   IN: Which DCGM field to inject the value for
     * samples       IN: Array of samples to inject
     * Nsamples      IN: Number of samples that are contained in samples[]
     *
     * Returns 0 on success
     *        <0 on error. See DCGM_ST_? #defines
     *
     */
    dcgmReturn_t InjectSamples(dcgm_field_entity_group_t entityGroupId,
                               dcgm_field_eid_t entityId,
                               unsigned short dcgmFieldId,
                               dcgmcm_sample_p samples,
                               int Nsamples);

    /*************************************************************************/
    /*
     * Free an array of DCGM samples, freeing any memory they might have
     * allocated
     *
     * samples      IN: Array of samples to free
     * Nsamples     IN: Number of samples that are contained in samples[]
     * dcgmFieldId  IN: Which DCGM field to free the value for. This is used to
     *                  get the field type.
     */
    dcgmReturn_t FreeSamples(dcgmcm_sample_p samples, int Nsamples, unsigned short dcgmFieldId);

    /*************************************************************************/
    /*
     * Do the actual work of updating all fields, looking to see if the fields
     * should be updated. Call this from the DcgmCacheThread.
     *
     * threadCtx           IO: Update thread context
     * earliestNextUpdate OUT: Timestamp in usec since 1970 of the next time
     *                         any stat should be updated (minimum timestamp)
     *
     */
    dcgmReturn_t ActuallyUpdateAllFields(dcgmcm_update_thread_t &threadCtx, timelib64_t *earliestNextUpdate);

    /*************************************************************************/
    /*
     * Populate a cache manager field info structure
     *
     * fieldInfo  IN,OUT: Structure to populate. fieldInfo->gpuId and fieldInfo->fieldId
     *                    are used to find the correct field record to query
     *
     *
     */
    dcgmReturn_t GetCacheManagerFieldInfo(dcgmCacheManagerFieldInfo_v4_t *fieldInfo);

    /*************************************************************************/
    /*
     * Populate a dcgmNvLinkStatus_v4 response with the NvLink link states
     * of every GPU and NvSwitch in the system
     */
    dcgmReturn_t PopulateNvLinkLinkStatus(dcgmNvLinkStatus_v4 &nvLinkStatus);

    /*************************************************************************/
    /*
     * Populate a dcgmMigHierarchy_v2 response with pairings of GPUs, GPU Instances,
     * and compute instances to display the hierarchy
     */
    dcgmReturn_t PopulateMigHierarchy(dcgmMigHierarchy_v2 &migHierarchy) const;

    /*************************************************************************/
    /*
     * Pass commands on to NVML to create a MIG entity
     */
    dcgmReturn_t CreateMigEntity(const dcgmCreateMigEntity_v1 &cme);

    /*************************************************************************/
    /*
     * Pass commands on to NVML to delete a MIG entity
     */
    dcgmReturn_t DeleteMigEntity(const dcgmDeleteMigEntity_v1 &cme);

    /*************************************************************************/
    /*
     * Get the state of NvLinks for a given entity. linkStates should be the following sizes:
     * DCGM_NVLINK_MAX_LINKS_PER_GPU for entityGroupId == DCGM_FE_GPU
     * DCGM_NVLINK_MAX_LINKS_PER_NVSWITCH for entityGroupId == DCGM_FE_SWITCH
     *
     */
    dcgmReturn_t GetEntityNvLinkLinkStatus(dcgm_field_entity_group_t entityGroupId,
                                           dcgm_field_eid_t entityId,
                                           dcgmNvLinkLinkState_t *linkStates);

    /*************************************************************************/
    /*
     * Map GPU ID to nvml index
     *
     * Returns NVML index on success. < 0 on failure (DCGMCM_ST_? #define)
     *
     */
    int GpuIdToNvmlIndex(unsigned int gpuId);

    /*************************************************************************/
    /*
     * Map NVML index to gpuId
     *
     * Returns gpuId
     *
     */
    unsigned int NvmlIndexToGpuId(int nvmlIndex);

    /*************************************************************************/
    /*
     * Returns whether or not a GPU is on the allowlist to run DCGM
     *
     */
    int IsGpuAllowlisted(unsigned int gpuId);

    /*************************************************************************/
    /*
     * Returns whether a given entityId is valid or not
     */
    bool GetIsValidEntityId(dcgm_field_entity_group_t entityGroupId, dcgm_field_eid_t entityId);

    /*************************************************************************/
    /*
     * Add a fake, injection-only GPU to the cache manager and set the PCI
     * device id as well as the subsystem id
     *
     * Returns gpuId of the fake GPU that was created or DCGM_GPU_ID_BAD if one
     *         could not be created
     *
     */
    unsigned int AddFakeGpu(unsigned int pciDeviceId, unsigned int pciSubSystemId);

    /*************************************************************************/
    /*
     * Add a fake, injection-only GPU to the cache manager
     *
     * Returns gpuId of the fake GPU that was created or DCGM_GPU_ID_BAD if one
     *         could not be created
     *
     */
    unsigned int AddFakeGpu(void);

    /*************************************************************************/
    /*
     * Add a fake, injection-only compute instance to the cache manager
     *
     * Returns the ID of the fake compute instance that was created or DCGM_GPU_ID_BAD if one
     *         could not be created
     *
     */
    dcgm_field_eid_t AddFakeComputeInstance(dcgm_field_eid_t parentId);

    /*************************************************************************/
    /*
     * Add a fake, injection-only GPU instance to the cache manager
     *
     * Returns the ID of the fake GPU instance that was created or DCGM_GPU_ID_BAD if one
     *         could not be created
     *
     */
    dcgm_field_eid_t AddFakeInstance(dcgm_field_eid_t parentId);

    /*************************************************************************/
    /*
     * Set the link state for a GPU's NvLink link
     *
     * gpuId     IN: ID of the GPU
     * linkId    IN: Link index to set the state of (0 to (DCGM_NVLINK_MAX_LINKS_PER_GPU-1))
     * linkState IN: State of the link to set
     *
     * Returns DCGM_ST_OK on success
     *         Other DCGM_ST_? error code on failure.
     *
     */
    dcgmReturn_t SetGpuNvLinkLinkState(unsigned int gpuId, unsigned int linkId, dcgmNvLinkLinkState_t linkState);


    /*************************************************************************/
    /*
     * Set the link state for an Entity's NvLink link
     *
     * entityGroupId IN: Entity group of the entity
     * entityId      IN: Entity ID of the entity
     * linkId        IN: Link index (portId for NvSwitches)
     * linkState     IN: State of the link to set
     *
     * Returns DCGM_ST_OK on success
     *         Other DCGM_ST_? error code on failure.
     *
     */
    dcgmReturn_t SetEntityNvLinkLinkState(dcgm_field_entity_group_t entityGroupId,
                                          dcgm_field_eid_t entityId,
                                          unsigned int linkId,
                                          dcgmNvLinkLinkState_t linkState);

    /*************************************************************************/
    /*
     * Are all of the GPUIDs in this group the same SKU?
     *
     * gpuIds IN: GPU Ids to compare for SKU equivalence. Note that this list
     *            is passed by reference, so make a copy of any thread-unsafe list
     *
     * Returns 1 if all of the GPUs of this group are the same
     *         0 if any of the GPUs of this group are different from each other
     *
     */
    int AreAllGpuIdsSameSku(std::vector<unsigned int> &gpuIds);

    /*************************************************************************/
    /*
     * Get runtime stats for the cache manager
     *
     * stats   OUT: Runtime stats of the cache manager
     */
    void GetRuntimeStats(dcgmcm_runtime_stats_p stats);

    /*************************************************************************/
    /*
     * Add field watches for the given vGPU instance
     *
     */
    void WatchVgpuFields(nvmlVgpuInstance_t vgpuId);

    /*************************************************************************/
    /*
     * Remove all field watches and clear the cache for the given vGPU instance
     *
     */
    dcgmReturn_t UnwatchVgpuFields(nvmlVgpuInstance_t vgpuId);

    /*************************************************************************/
    /*
     * Manage the dynamic addition/removal of the vGPUs.
     * Active vGPU instance (linked) list is maintained per GPU within the function depending on addition of
     * new vGPU instance or removal of any running vGPU instance.
     * Also vgpuIndex is mapped to the vGPU instances running within range specified for the nvmlIndex.
     * First element of vgpuInstanceIds array passed as input must hold the count of vGPU instances running.
     *
     * Note that index 0 of vgpuInstanceIds is ignored
     *
     * Returns 0 if OK
     *        <0 DCGM_ST_? on module error
     */
    dcgmReturn_t ManageVgpuList(unsigned int gpuId, nvmlVgpuInstance_t *vgpuInstanceIds);

    /*************************************************************************/
    /*
     * Get and store the affinity information from NVML for this box
     */
    dcgmReturn_t CacheTopologyAffinity(dcgmcm_update_thread_t &threadCtx, timelib64_t now, timelib64_t expireTime);

    /*************************************************************************/
    /*
     * From gpuIds, select numGpus of those which are the topologically best fit for each other, writing that
     * information into outputGpus as a bitmask.
     *
     * Returns 0 if OK
     *        <0 DCGM_ST_* on module error
     */
    dcgmReturn_t SelectGpusByTopology(std::vector<unsigned int> &gpuIds, uint32_t numGpus, uint64_t &outputGpus);

    /*************************************************************************/
    /*
     * Fill the passed in affinity struct with the affinity information for this node.
     *
     * Returns 0 if OK
     *         DCGM_ST_* on module error
     */
    dcgmReturn_t PopulateCpuAffinity(dcgmAffinity_t &affinity);

    /*************************************************************************/
    /*
     * Return a topology struct populated with the information on the NVLink for
     * this system.
     *
     * Returns a pointer to the populated topology object
     *         NULL on error
     */
    dcgmTopology_t *GetNvLinkTopologyInformation();

    /*************************************************************************/
    /*
     * Cache the topology information relevant to NvLink for this host.
     *
     * Returns 0 if ok
     *         DCGM_ST_* on module error
     */
    dcgmReturn_t CacheTopologyNvLink(dcgmcm_update_thread_t &threadCtx, timelib64_t now, timelib64_t expireTime);

    /*************************************************************************/
    /*
     * Get the cache manager's list of valid field IDs.
     *
     * includeModulePublished IN: Should we include fields that are module-published in this list?
     *
     */
    void GetValidFieldIds(std::vector<unsigned short> &validFieldIds, bool includeModulePublished = true);

    /*************************************************************************/
    /*
     * Get a copy of the watch info for a given entity for a given field into watchInfo.
     * This is useful for testing purposes. This information is a snapshot of what the cache manager
     * has internally for the entity.
     *
     * Returns: DCGM_ST_OK on success.
     *          DCGM_ST_NO_DATA if the watch object cannot be found.
     *
     */
    dcgmReturn_t GetEntityWatchInfoSnapshot(dcgm_field_entity_group_t entityGroupId,
                                            dcgm_field_eid_t entityId,
                                            unsigned int fieldId,
                                            dcgmcm_watch_info_p watchInfo);

    /*************************************************************************/
    /*
     * Handle a client disconnecting from the host engine
     */
    void OnConnectionRemove(dcgm_connection_id_t connectionId);

    /*************************************************************************/
    /*
     * Main loop thread for the event reading thread this is public so it can
     * be seen from DcgmCacheManagerEventThread. This method should not be called
     * externally.
     *
     */
    void EventThreadMain(DcgmCacheManagerEventThread *eventThread);

    /*************************************************************************/
    /*
     * Find all GPUs in the system and set their state appropriately in this
     * object.
     *
     * RETURNS: DCGM_ST_OK on success
     *          DCGM_ST_GENERIC_ERROR on NVML error
     */
    dcgmReturn_t AttachGpus(void);

    /*************************************************************************/
    /*
     * Find all GPU instances and compute instacnes in the system and set their state appropriately in this
     * object.
     *
     * RETURNS: DCGM_ST_OK on success
     *          DCGM_ST_GENERIC_ERROR on NVML error
     */
    dcgmReturn_t InitializeGpuInstances(dcgmcm_gpu_info_t &gpuInfo);

    /*************************************************************************/
    /**
     * Clear Mig Information for this GPU
     *
     * @param gpuInfo - the struct representing the GPU being cleared
     */
    void ClearGpuMigInfo(dcgmcm_gpu_info_t &gpuInfo);

    /*************************************************************************/
    /*
     * Adds the newly detected GPU list to our internal list by matching UUIDs
     */
    void MergeNewlyDetectedGpuList(dcgmcm_gpu_info_p detectedGpus, int count);

    /*************************************************************************/
    /*
     * Detach from all GPUs in the system and set their state appropriately.
     *
     * RETURNS: DCGM_ST_OK on success
     *          DCGM_ST_GENERIC_ERROR on NVML error
     */
    dcgmReturn_t DetachGpus(void);

    /*************************************************************************/
    /*
     * Gets the index of the GPU with a matching gpuId from m_gpus.
     *
     * RETURNS: the index if found
     *          -1 if no matching GPU was found
     */
    int FindGpuIdsIndex(unsigned int gpuId);

    /*************************************************************************/
    /**
     * Gets the GPU id for this entity - used to ensure that we are
     * NOTE: only public for unit testing
     *
     */
    dcgmReturn_t GetGpuId(unsigned int entityGroupId, unsigned int entityId, unsigned int &gpuId);

    /*************************************************************************/
    /**
     * Returns true if the specified device has MIG mode enabled.
     *
     * @param gpuIndex - the index of the GPU
     * @return true if the specified device has MIG mode enabled, false otherwise
     */
    bool IsGpuMigEnabled(unsigned int gpuIndex);

    /*************************************************************************/
    /**
     * Returns true if any GPU has MIG mode enabled
     *
     * @return true if any GPU has MIG mode enabled
     */
    bool IsMigEnabledAnywhere();

    /**
     * Notifies subscribers (if any) that MIG has been reconfigured
     * (public for unit tests)
     */
    /*************************************************************************/
    void NotifyMigUpdateSubscribers(unsigned int gpuId);

    /**
     * Generates the appropriate value for CUDA_VISIBLE_DEVICES for the specified
     * device
     * (public for unit tests only)
     */
    /*************************************************************************/
    void GenerateCudaVisibleDevicesValue(unsigned int gpuId,
                                         unsigned int entityGroupId,
                                         unsigned int entityId,
                                         std::stringstream &valbuf);

    /*************************************************************************/

    /**
     * Convert the NVML compute instance id to the DCGM compute instance id
     *
     * @param gpuId[in]                 - the id of the GPU whose instance we're dealing with
     * @param nvmlComputeInstanceId[in] - the NVML compute instance id we're converting
     * @param nvmlGpuInstanceId[in]     - the NVML GPU instance id for the compute instance we're converting
     *
     * @return the equivalent DCGM compute instance id
     *         or DCGM_BLANK_ENTITY_ID if no such compute instance exists on this GPU and GPU instance
     */
    dcgm_field_eid_t GetComputeInstanceEntityId(unsigned int gpuId,
                                                DcgmNs::Mig::Nvml::ComputeInstanceId const &nvmlComputeInstanceId,
                                                DcgmNs::Mig::Nvml::GpuInstanceId const &nvmlGpuInstanceId);

    /*************************************************************************/
    /**
     * Convert the NVML GPU instance id to the DCGM GPU instance id
     *
     * @param gpuId[in]             - the id of the GPU whose instance we're dealing with
     * @param nvmlGpuInstanceId[in] - the NVML GPU instance id we're converting
     * @return the equivalent DCGM GPU instance id
     *         or DCGM_BLANK_ENTITY_ID if no such instance exists on this GPU
     */
    dcgm_field_eid_t GetInstanceEntityId(unsigned int gpuId, DcgmNs::Mig::Nvml::GpuInstanceId const &nvmlGpuInstanceId);

    /*************************************************************************/
    dcgmMigProfile_t GetInstanceProfile(unsigned int gpuId, DcgmNs::Mig::Nvml::GpuInstanceId const &nvmlGpuInstanceId);
    dcgmReturn_t GetMigGpuPopulation(unsigned int gpuId, size_t *capacityGpcs, size_t *usedGpcs) const;
    dcgmReturn_t GetMigInstancePopulation(unsigned int gpuId,
                                          DcgmNs::Mig::Nvml::GpuInstanceId const &instanceId,
                                          size_t *capacityGpcs,
                                          size_t *usedGpcs) const;
    dcgmReturn_t GetMigComputeInstancePopulation(unsigned int gpuId,
                                                 DcgmNs::Mig::Nvml::GpuInstanceId const &instanceId,
                                                 DcgmNs::Mig::Nvml::ComputeInstanceId const &computeInstanceId,
                                                 size_t *capacityGpcs,
                                                 size_t *usedGpcs);
    std::optional<unsigned int> GetGpuIdForEntity(dcgm_field_entity_group_t entityGroupId, dcgm_field_eid_t entityId);

    /*************************************************************************/
    /**
     * For the given entityId and entityGroupId looks for corresponding GpuInstance and/or ComputeInstance
     * @param[in]  entityPair           EntityId and EntityGroupId for the lookup
     * @param[out] gpuId                GpuId of the found MIG instance
     * @param[out] instanceId           MIG GpuInstance of the found MIG Instance
     * @param[out] computeInstanceId    MIG ComputeInstance of the found MIG Instance
     * @return
     *       \c\b DCGM_ST_OK        The MIG Instance with the given entityId/entityGroupId was successfully found<br>
     *       \c\b DCGM_ST_BADPARAM  Some of the \b out parameters, necessary for the given entity were nullptr<br>
     *       \c\b DCGM_ST_NO_DATA   A MIG entity with the given entityId/entityGroupId was not found<br>
     */
    dcgmReturn_t GetMigIndicesForEntity(dcgmGroupEntityPair_t const &entityPair,
                                        unsigned int *gpuId,
                                        DcgmNs::Mig::GpuInstanceId *instanceId,
                                        DcgmNs::Mig::ComputeInstanceId *computeInstanceId) const;
    /*************************************************************************/
    /**
     *
     * Filter a list of entities to only include those that should be serviced
     * by perfworks for DCP metrics. It's assumed that the rest are handled
     * by NVML GPM or not at all.
     *
     * @param entities[in,out] Array of entities to filter. Only entities that
     *                         should be serviced by perfworks will remain after
     *                         this call.
     */
    void GetProfModuleServicedEntities(std::vector<dcgmGroupEntityPair_t> &entities);

    /*************************************************************************/
    /**
     * Function to return whether the given entity pair supports GPU Performance Monitoring (GPM)
     *
     * If is this true, then the entity's profiling metrics are serviced by the
     * cache manager rather than the profiling module.
     *
     * @return true if the entity supports GPM. false if not.
     */
    bool EntityPairSupportsGpm(dcgmGroupEntityPair_t const &entityPair);

    /*************************************************************************/
    /**
     * Function to return whether the given entity key supports GPU Performance Monitoring (GPM)
     *
     * If is this true, then the entity's profiling metrics are serviced by the
     * cache manager rather than the profiling module.
     *
     * @return true if the entity supports GPM. false if not.
     */
    bool EntityKeySupportsGpm(const dcgm_entity_key_t &entityKey);

    /*************************************************************************/

    /*************************************************************************/
    /*
     * Helper functions to append values to our internal data structure
     *
     * Note that threadCtx has entries that should be set before this call:
     * - entityKey MUST be set to the key information for this update
     * - fvBuffer can be set if you want this value to be buffered. This is useful
     *       for capturing updates and sending them to other subsystems or clients
     * - watchInfo can be set if you want this value to be cached
     *
     * Returns 0 on success
     *         DCGM_ST_? #define on error
     *
     */
    dcgmReturn_t AppendEntityString(dcgmcm_update_thread_t &threadCtx,
                                    const char *value,
                                    timelib64_t timestamp,
                                    timelib64_t oldestKeepTimestamp);
    dcgmReturn_t AppendEntityDouble(dcgmcm_update_thread_t &threadCtx,
                                    double value1,
                                    double value2,
                                    timelib64_t timestamp,
                                    timelib64_t oldestKeepTimestamp);
    dcgmReturn_t AppendEntityInt64(dcgmcm_update_thread_t &threadCtx,
                                   long long value1,
                                   long long value2,
                                   timelib64_t timestamp,
                                   timelib64_t oldestKeepTimestamp);
    dcgmReturn_t AppendEntityBlob(dcgmcm_update_thread_t &threadCtx,
                                  void *value,
                                  int valueSize,
                                  timelib64_t timestamp,
                                  timelib64_t oldestKeepTimestamp);

    nvmlDevice_t GetNvmlDeviceFromEntityId(dcgm_field_eid_t entityId) const;

#ifdef INJECTION_LIBRARY_AVAILABLE
    dcgmReturn_t InjectNvmlGpu(dcgm_field_eid_t gpuId,
                               const char *key,
                               const injectNvmlVal_t *extraKeys,
                               unsigned int extraKeyCount,
                               const injectNvmlRet_t &injectNvmlRet);

    dcgmReturn_t InjectNvmlGpuForFollowingCalls(dcgm_field_eid_t gpuId,
                                                const char *key,
                                                const injectNvmlVal_t *extraKeys,
                                                unsigned int extraKeyCount,
                                                const injectNvmlRet_t *injectNvmlRets,
                                                unsigned int retCount);

    dcgmReturn_t InjectedNvmlGpuReset(dcgm_field_eid_t gpuId);

    dcgmReturn_t GetNvmlInjectFuncCallCount(injectNvmlFuncCallCounts_t *funcCallCounts);

    dcgmReturn_t ResetNvmlInjectFuncCallCount();

    dcgmReturn_t RemoveNvmlInjectedGpu(char const *uuid);

    dcgmReturn_t RestoreNvmlInjectedGpu(char const *uuid);
#endif

    dcgmReturn_t CreateNvmlInjectionDevice(unsigned int index);

    dcgmReturn_t InjectNvmlFieldValue(dcgm_field_eid_t gpuId,
                                      const dcgmFieldValue_v1 &value,
                                      dcgm_field_meta_p fieldMeta);

    /*
     * Inspects the nvmlGpuFabricInfoV_t struct to find fabric manager and error (if any)
     *
     * @param gpuFabricInfo (I) - the struct returned from NVML
     * @param status        (O) - the status of the fabric manager
     * @param fmError       (O) - the error reported. This is set to a blank value unless the fabric manager has
     * finished coming up
     *
     * @return DCGM_ST_BADPARAM if a status couldn't be read from gpuFabricInfo, else DCGM_ST_OK
     */
    static dcgmReturn_t GetFMStatusFromStruct(nvmlGpuFabricInfoV_t const &gpuFabricInfo,
                                              dcgmFabricManagerStatus_t &status,
                                              uint64_t &fmError);

    dcgmReturn_t ReadFabricManagerStatusField(dcgmcm_update_thread_t &threadCtx,
                                              nvmlDevice_t nvmlDevice,
                                              dcgm_field_meta_p fieldMeta,
                                              timelib64_t now,
                                              timelib64_t expireTime);

#ifndef TEST_DCGMCACHEMANAGER
private:
#endif

    int m_pollInLockStep; /* Whether to poll when told to (1) or at the
                                    frequency of the most frequent stat being tracked (0) */

    timelib64_t m_maxSampleAgeUsec; /* Maximum time to keep a sample of ANY field, defaults to 1 hour */

    /* The following are set by ReadAndCacheDriverVersions() */
    std::string m_driverVersion; /* Version string of the attached driver like "4184003" (418.40.03)
                                    so the strings can be compared. Set by AttachGpus() and protect by m_mutex. */
    std::atomic_bool
        m_driverIsR450OrNewer; /* Is the driver r450.00 or newer? This is the driver version of nvml_11.0.h APIs */

    std::atomic_bool
        m_driverIsR520OrNewer; /* Is the driver r450.00 or newer? This is the driver version of nvml_11.0.h APIs */

    unsigned int m_driverMajorVersion;                          /* Major driver version, eg. 470, 510, etc */
    unsigned int m_numGpus;                                     /* Number of entries in m_gpus[] that are valid */
    unsigned int m_numFakeGpus;                                 /* Number of entries in m_gpus[] that are fake */
    unsigned int m_numInstances;                                // Number of total GPU instances created
    unsigned int m_numComputeInstances;                         // Number of total compute instances created
    std::array<dcgmcm_gpu_info_t, DCGM_MAX_NUM_DEVICES> m_gpus; /* All of the GPUs we know about, indexed by gpuId */

    bool m_nvmlInitted; /* Tracks whether or not NVML has been initialized. since NVML keeps a count
                           of initializations, we don't want to double initialize or we won't be able
                           to detach and attach to GPUs correctly. */

    std::vector<nvmlExcludedDeviceInfo_t> m_gpuExcludeList; /* Array of GPUs that have been excluded by the driver */

    DcgmMutex *m_mutex;                     /* Lock used for protecting data structures within this class */
    unsigned int m_inDriverCount;           // Count of threads currently in driver calls
    unsigned int m_waitForDriverClearCount; // Count of threads waiting for the driver to be clear

    /* Track per-entity watches of fields. Use GetEntityWatchInfo() method to get a
       pointer to an element of this.
       Is a hash of dcgm_entity_key_t -> entity_watch_table_t */
    hashtable_t *m_entityWatchHashTable;

    /* Cache of which PIDs we have already saved to the cache with which start times
     * This saves us having to scan the entire accounting data structure to find
     * which PIDs we have already saved */
    keyedvector_p m_accountingPidsSeen;

    /* NVML events */

    /* Mask of current events being monitored. See nvmlEventType* in nvml.h */
    unsigned long long m_currentEventMask[DCGM_MAX_NUM_DEVICES];
    bool m_nvmlEventSetInitialized; /* Is m_nvmlEventSet initialized */
    nvmlEventSet_t m_nvmlEventSet;

    /* Vector of the field IDs that are actually defined. This will never change
     * after start-up, so iterators for this can be used without locking */
    std::vector<unsigned short> m_allValidFieldIds;

    /* Runtime stats of the cache manager */
    dcgmcm_runtime_stats_t m_runStats;

    DcgmCacheManagerEventThread *m_eventThread { nullptr }; /* Thread for reading NVML events */

    DcgmKmsgReaderThread *m_kmsgThread { nullptr }; /* Thread for reading additional NVML events in /dev/kmsg */

    bool m_haveAnyLiveSubscribers; /* Has any watch registered to receive live updates? */

    std::vector<dcgmSubscribedFvUpdateCBEntry_t> m_onFvUpdateCBs; /* Callbacks to invoke when a
                                                                    subscribed field value updates */

    std::vector<dcgmcmEventSubscription_t> m_subscriptions[DcgmcmEventTypeSize]; // Stored callbacks

    DcgmGpmManager m_gpmManager; // Interfaces with NVML GPU Performance Monitoring (GPM) APIs

    DcgmMigManager m_migManager; // Tracks MIG information for quick lookup
                                 // Tracks the timestamp of a user request that we delay mig reconfig processing
    timelib64_t m_delayedMigReconfigProcessingTimestamp;

    DcgmMutex *m_nvmlTopoMutex; /* NVML topology APIs aren't thread safe. Make sure only one thread is using them */

    bool m_forceProfMetricsThroughGpm; /* Should we force profiling metrics through GPM? True=yes. False=no. This
                                          is useful for using the GPM simulator in NVML to test end-to-end with
                                          control values */

    DcgmInjectionNvmlManager m_nvmlInjectionManager;

    std::unique_ptr<dcgmcm_update_thread_t>
        m_updateThreadCtx; /* Thread context for the update thread (our TaskRunner) under the run() method */

    bool m_nvmlLoaded; /* true if NVML was successfully loaded */

    /*
     * UUIDs of GPUs in m_gpus[] whose status have been set to DcgmEntityStatusLost
     */
    std::unordered_set<std::string> m_lostGpus;

    std::unordered_map<std::string, unsigned int> pciBusGpuIdMap;

    /*
     * Set by DcgmCacheManagerEventThread when NVML driver timeout XID is detected, and NVML calls need
     * to be skipped.
     */
    std::atomic<bool> m_skipDriverCalls;

    /*************************************************************************/
    /*
     * Build vector of gpu info for topology functions.
     */
    std::vector<dcgm_topology_helper_t> GetTopologyHelper(bool includeLinkStatus = false);

    /*************************************************************************/
    /*
     * Helper function for DCGM_FI_DEV_FB_* fields.
     */
    void ReadAndCacheFBMemoryInfo(unsigned int gpuId,
                                  nvmlDevice_t nvmlDevice,
                                  dcgmcm_update_thread_t &threadCtx,
                                  dcgmcm_watch_info_p watchInfo,
                                  timelib64_t expireTime,
                                  unsigned short fieldId);

    /*************************************************************************/
    /*
     * Look at watchInfo's watchers and see if any have live subscriptions
     *
     * If any do, mark them in watchInfo->bufferedWatchers
     */
    void MarkSubscribersInThreadCtx(dcgmcm_update_thread_t &threadCtx, dcgmcm_watch_info_p watchInfo);

    /*************************************************************************/
    /*
     * Call callbacks for any FVs that have been buffered by this update thread
     *
     */
    dcgmReturn_t UpdateFvSubscribers(dcgmcm_update_thread_t &updateCtx);

    /*************************************************************************/
    /*
     * Do some common pre-checks of a watchInfo before samples are processed for it
     * and return common error codes if any common conditions are encountered.
     *
     * Note: This code assumes that the cache manager is locked
     *
     * Returns: DCGM_ST_OK if samples can be returned from this watchInfo
     *          Other DCGM_ST_? status codes that should be returned to the caller on error.
     */
    dcgmReturn_t PrecheckWatchInfoForSamples(dcgmcm_watch_info_p watchInfo);

    /*************************************************************************/
    /*
     * Helper function to enforce the quota for a watchInfo's time series.
     *
     * watchInfo           IO: Watch info to check + modify
     * timestamp           IN: Current timestamp
     * oldestKeepTimestamp IN: Oldest timestamp to leave in the time series.
     *                         Any records with timestamps older than this
     *                         will be removed.
     */
    dcgmReturn_t EnforceWatchInfoQuota(dcgmcm_watch_info_p watchInfo,
                                       timelib64_t timestamp,
                                       timelib64_t oldestKeepTimestamp);

    /*************************************************************************/
    /*
     * Helper functions for adding or removing watch info classes
     */
    dcgmcm_watch_info_p AllocWatchInfo(dcgm_entity_key_t entityKey);
    void FreeWatchInfo(dcgmcm_watch_info_p watchInfo);

    /*************************************************************************/
    /*
     * Allocate the timeSeries part of a watchInfo
     *
     * Returns: DCGM_ST_OK on success
     *          Any other DCGM_ST_? on error
     */
    dcgmReturn_t AllocWatchInfoTimeSeries(dcgmcm_watch_info_p watchInfo, int tsType);

    /*************************************************************************/
    /*
     * Add a watcher on a field or update the existing watcher if newWatcher is
     * already in the list
     *
     * NOTE: This function assumes the cache manager is already locked so that
     *       watchInfo is safe to modify
     *
     * RETURNS: Always returns DCGM_ST_OK for now
     *
     */
    dcgmReturn_t AddOrUpdateWatcher(dcgmcm_watch_info_p watchInfo,
                                    bool *wasAdded,
                                    dcgm_watch_watcher_info_t *newWatcher);

    /*************************************************************************/
    /*
     * Remove a watcher on a field
     *
     * NOTE: This function assumes the cache manager is already locked so that
     *       watchInfo is safe to modify
     *
     * RETURNS: DCGM_ST_OK if the watcher was found and removed
     *          DCGM_ST_NOT_WATCHED if the given watcher wasn't found
     *
     */
    dcgmReturn_t RemoveWatcher(dcgmcm_watch_info_p watchInfo, dcgm_watch_watcher_info_t *watcher);

    /*************************************************************************/
    /*
     * Cache a snapshot of all valid watch objects so we don't need to hold
     * the cache manager mutex while we iterate over them. This is useful in
     * avoiding deadlocks if you'll be RPCing out of the cache manager.
     *
     * NOTE: You still need to hold the cache manager mutex to modify any entry.
     *
     */
    void GetAllWatchObjects(std::vector<dcgmcm_watch_info_p> &watchers);

    /*************************************************************************/
    /*
     * Update the update update frequency and quota based on the minimum values
     * from all of our watchers
     *
     * NOTE: This function assumes the cache manager is already locked so that
     *       watchInfo is safe to modify
     */
    dcgmReturn_t UpdateWatchFromWatchers(dcgmcm_watch_info_p watchInfo);

    /*************************************************************************/
    /*
     * Tell the cache manager to update its NvLink link state for a given gpuId
     *
     */
    dcgmReturn_t UpdateNvLinkLinkState(unsigned int gpuId);

    /*************************************************************************/
    /*
     * Convert a entityId and fieldId to a watch key to be used as an index
     * against m_entityWatches.
     *
     * Returns: !0 watch key on success
     *           0 on error
     *
     */
    void EntityIdToWatchKey(dcgm_entity_key_t *watchKey,
                            dcgm_field_entity_group_t entityGroupId,
                            dcgm_field_eid_t entityId,
                            unsigned int fieldId);

    /*************************************************************************/
    /*
     * Get the watch context structure for a field, given it's gpuId and fieldId
     *
     * entityGroupId: ID of the entity group
     * entityId: ID of the entity within the group. This should be gpuId for GPUs and VGPU ID for VGPUs
     * fieldId: fieldId of the field
     * createIfNotExists: If the watchInfo doesn't already exist, should we create it? 1=yes. 0=no.
     *
     * Returns: pointer to watch context structure
     *          NULL on error (likely out of memory)
     *
     */
    dcgmcm_watch_info_p GetEntityWatchInfo(dcgm_field_entity_group_t entityGroupId,
                                           dcgm_field_eid_t entityId,
                                           unsigned int fieldId,
                                           int createIfNotExists);
    dcgmcm_watch_info_p GetGlobalWatchInfo(unsigned int fieldId, int createIfNotExists);

    /*************************************************************************/
    /*
     * Get the next watch_info structure that is valid for a given nvmlIndex
     *
     * This method is useful for iterating over all watched fields of a GPU
     *
     * Pass *validFieldIndex as 0 on the first call
     *
     * RETURNS: Pointer to watch info structure on success
     *          NULL if we've reached the end of the watches for this nvmlIndex
     *
     */
    dcgmcm_watch_info_p GetNextEntityWatchInfo(dcgm_field_entity_group_t entityGroupId,
                                               dcgm_field_eid_t entityId,
                                               unsigned int *validFieldIndex);

    /*************************************************************************/
    /*
     * Check to see if an accounting PID has already been cached at a given timestamp
     *
     * RETURNS: 1 if PID has been cached
     *          0 if not
     */
    int HasAccountingPidBeenSeen(unsigned int pid, timelib64_t timestamp);

    /*************************************************************************/
    /*
     * Mark a PID as having been cached
     *
     * RETURNS: 0 if OK
     *         <0 on error. See DCGM_ST_? enumerations for details.
     *
     */
    dcgmReturn_t CacheAccountingPid(unsigned int pid, timelib64_t timestamp);

    /*************************************************************************/
    /*
     * Clear all values from the accounting PID cache
     *
     * RETURNS: Nothing
     *
     */
    void EmptyAccountingPidCache();

    /*************************************************************************/
    /*
     * Read a value for a GPU field and cache or buffer it. See
     * dcgmcm_update_thread_t documentation for details.
     *
     * Returns 0 if OK
     *        <0 DCGM_ST_? on module error
     */
    dcgmReturn_t BufferOrCacheLatestGpuValue(dcgmcm_update_thread_t &threadCtx, dcgm_field_meta_p fieldMeta);

    /*************************************************************************/
    /*
     * Helper method to add entity field watches
     */
    dcgmReturn_t AddEntityFieldWatch(dcgm_field_entity_group_t fieldEntityGroup,
                                     unsigned int entityId,
                                     unsigned short dcgmFieldId,
                                     timelib64_t monitorIntervalUsec,
                                     double maxSampleAge,
                                     int maxKeepSamples,
                                     DcgmWatcher watcher,
                                     bool subscribeForUpdates,
                                     bool updateOnFirstWatch,
                                     bool &wereFirstWatcher);

    /*************************************************************************/
    /*
     * Helper method to remove device field watches
     */
    dcgmReturn_t RemoveEntityFieldWatch(dcgm_field_entity_group_t fieldEntityGroup,
                                        unsigned int entityId,
                                        unsigned short dcgmFieldId,
                                        int clearCache,
                                        DcgmWatcher watcher);

    /*************************************************************************/
    /*
     * Clear the contents of a watch object in the cache manager
     *
     * clearCache    IN: Whether to clear cached data for this entity. 1=yes. 0=no
     *
     * NOTE: Assumes the cache manager is locked by the caller
     */
    void ClearWatchInfo(dcgmcm_watch_info_p watchInfo, int clearCache);


    /*************************************************************************/
    /*
     * Clear all entities from the cache manager. The watch objects will remain
     * but their contents will be cleared
     *
     * clearCache    IN: Whether to clear cached data for this entity. 1=yes. 0=no
     */
    dcgmReturn_t ClearAllEntities(int clearCache);

    /*************************************************************************/
    /*
     * Clear an entity from the cache manager. The watch object will remain
     * but its contents will be cleared
     *
     * entityGroupId IN: Group id of the entity to clear
     * entityId      IN: Entity within entityGroupId to clear
     * clearCache    IN: Whether to clear cached data for this entity. 1=yes. 0=no
     *
     */
    dcgmReturn_t ClearEntity(dcgm_field_entity_group_t entityGroupId, dcgm_field_eid_t entityId, int clearCache);

    /*************************************************************************/
    /*
     * Helper method to add global watches
     */
    dcgmReturn_t AddGlobalFieldWatch(unsigned short dcgmFieldId,
                                     timelib64_t monitorIntervalUsec,
                                     double maxSampleAge,
                                     int maxKeepSamples,
                                     DcgmWatcher watcher,
                                     bool subscribeForUpdates,
                                     bool updateOnFirstWatch,
                                     bool &wereFirstWatcher);

    /*************************************************************************/
    /*
     * Helper method to Stop and remove monitoring of a global field
     *
     */
    dcgmReturn_t RemoveGlobalFieldWatch(unsigned short dcgmFieldId, int clearCache, DcgmWatcher watcher);

    /*************************************************************************/
    /*
     * Helper method to return whether (true) or not (false) a fieldId is published
     * by a module. These fieldIds will not be updated by the DCGM cache manager.
     *
     */
    bool IsModulePushedFieldId(unsigned int fieldId);

    dcgmReturn_t AppendDeviceSupportedClocks(dcgmcm_update_thread_t &threadCtx,
                                             nvmlDevice_t nvmlDevice,
                                             timelib64_t timestamp,
                                             timelib64_t oldestKeepTimestamp);

    dcgmReturn_t AppendDeviceAccountingStats(dcgmcm_update_thread_t &threadCtx,
                                             unsigned int pid,
                                             nvmlAccountingStats_t *nvmlAccountingStats,
                                             timelib64_t timestamp,
                                             timelib64_t oldestKeepTimestamp);

    /*************************************************************************/
    /* Helper methods to cache individual metrics */
    void ReadAndCacheNvLinkBandwidth(dcgmcm_update_thread_t &threadCtx,
                                     nvmlDevice_t nvmlDevice,
                                     unsigned int scopeId,
                                     DcgmcmDirection_t directon,
                                     timelib64_t expireTime);

    void ReadAndCacheNvLinkData(dcgmcm_update_thread_t &threadCtx,
                                nvmlNvLinkErrorCounter_t fieldId,
                                nvmlDevice_t nvmlDevice,
                                unsigned int scopeId,
                                timelib64_t expireTime);

    void ReadAndCacheErrorCounts(dcgmcm_update_thread_t &threadCtx,
                                 nvmlDevice_t nvmlDevice,
                                 nvmlMemoryErrorType_t errorType,
                                 nvmlEccCounterType_t counterType,
                                 nvmlMemoryLocation_t locationType,
                                 timelib64_t expireTime);

    /*************************************************************************/
    /*
     * Helper to update all fields for a GPU that can be retrieved in batch
     * from NVML via their nvmlFieldId.
     *
     * threadCtx     IN: Thread context that has the following entries populated:
     *                   numFieldIds[gpuId] -> Number of entries in next two
     *                   fieldValueFields[gpuId] -> Field meta for each field
     *                   fieldValueWatchInfo[gpuId] -> Watch info for each field. NULL=don't cache (just buffer)
     * gpuId         IN: ID of the GPU to fetch fields for
     *
     */
    dcgmReturn_t ActuallyUpdateGpuFieldValues(dcgmcm_update_thread_t &threadCtx, unsigned int gpuId);

    /*************************************************************************/
    /*
     * Polling thread run() top level helpers
     *
     * DoOneUpdateAllFields returns the timestamp of when the next watch will need an
     * update in seconds since 1970.
     */
    timelib64_t DoOneUpdateAllFields(void);

    /*************************************************************************/
    /*
     * The part of run() that actually does work. This exists so that all
     * allocating and freeing is done by the parent run() and we don't need
     * a goto FAILED to cleanup in run().
     */
    void RunWrapped(void);

    /*************************************************************************/
    /*
     * Helpers to prepare or unprepare NVML for field updates for a given field ID.
     * This handles tasks like telling NVML to watch/unwatch accounting data
     *
     * NOTE: This function assumes it is inside of a Lock() / Unlock() pair.
     *
     */
    dcgmReturn_t NvmlPreWatch(unsigned int gpuId, unsigned short dcgmFieldId);
    dcgmReturn_t NvmlPostWatch(unsigned int gpuId, unsigned short dcgmFieldId);

    /*************************************************************************/
    /*
     * Returns whether the NV driver is at least as new as the given string.
     *
     * compareVersion is expected to be in the format "4188303" for version "418.83.03"
     *
     */
    bool DriverVersionIsAtLeast(std::string const &compareVersion);

    /*************************************************************************/
    /*
     * Helper method to populate m_driverVersion and m_driverIsR450OrNewer
     * based on the installed driver version returned from NVML.
     *
     */
    void ReadAndCacheDriverVersions(void);

    /*************************************************************************/
    /*
     * Helper method to manage watching NVML events. Since events are read
     * system wide, we need to look at all GPUs' watches to see which events
     * we care about
     *
     * NOTE: This function assumes it is inside of a Lock() / Unlock() pair.
     *       Currently, it is only called from NvmlPreWatch/NvmlPostWatch
     *
     * addWatchOnGpuId     IN: Optional GPU ID of a watch that will be created
     *                         after this call that we should prepare for. -1 = none
     * addWatchOnFieldId   IN: Optional DCGM field id of a watch that will be created
     *                         after this call that we should prepare for. 0 = none
     *
     *         Returns 0 on success
     *         DCGM_ST_? #define on error
     */
    dcgmReturn_t ManageDeviceEvents(unsigned int addWatchOnGpuId, unsigned short addWatchOnFieldId);

    /*
     * Check that the given field and gpuId are valid.
     */
    dcgmReturn_t CheckValidGlobalField(unsigned short dcgmFieldId);
    dcgmReturn_t CheckValidGpuField(unsigned int gpuId, unsigned short dcgmFieldId);

    /*************************************************************************/
    /*
     * Read the GPU exclusion list from the driver an cache it into m_gpuExclusionList
     *
     */
    dcgmReturn_t ReadAndCacheGpuExclusionList(void);

    /*************************************************************************/
    /*
     * Signifies a thread has entered the driver
     * NOTE: m_mutex must be locked before calling
     *
     * Checked by attaching and detaching to make sure unloading and loading NVML is ok
     */
    void MarkEnteredDriver();

    /*************************************************************************/
    /*
     * Signifies a thread has returned from the driver
     * NOTE: m_mutex must be locked before calling
     *
     * Checked by attaching and detaching to make sure unloading and loading NVML is ok
     */
    void MarkReturnedFromDriver();

    /*************************************************************************/
    /*
     * Tracks whether it's okay to enter the driver or proceed as though no one
     * is in the driver.
     *
     * @see AttachGpus(), DetachGpus(), MarkEnteredDriver()
     */
    void SynchronizeDriverEntries(unsigned int &countToWaitFor, unsigned int &waitingEntries, bool entering);

    /*****************************************************************************/
    /*
     * Simple wrapper for SynchronizeDriverEntries(); waits for nothing to be
     * using the driver
     */
    void WaitForThreadsToExitDriver();

    /*****************************************************************************/
    /*
     * Simple wrapper for SynchronizeDriverEntries(); waits for the driver to be
     * okay to use again after detaching
     */
    void WaitForDriverToBeReady();

    /*************************************************************************/
    /*
     * Inserts an NVML error value translated to the relevant field type.
     */
    void InsertNvmlErrorValue(dcgmcm_update_thread_t &threadCtx,
                              unsigned char fieldType,
                              nvmlReturn_t err,
                              timelib64_t expireTime);

    /*************************************************************************/
    /*
     * Frees up the nvml event set and updates the internal tracking data
     */
    void UninitializeNvmlEventSet();

    /*************************************************************************/
    /*
     * Initializes the nvml event set and updates the internal tracking data
     */
    dcgmReturn_t InitializeNvmlEventSet();

    /*************************************************************************/
    /*
     * Read the chip architecture from NVML. Note that this may be inferred
     * from the compute capability if the chip arch API is not implemented in
     * NVML
     */
    dcgmReturn_t HelperGetLiveChipArch(nvmlDevice_t nvmlDevice, dcgmChipArchitecture_t &arch);


    /*************************************************************************/
    /**
     * Record an Xid event for a given gpuId
     */
    void RecordXidForGpu(unsigned int gpuId,
                         dcgmcm_update_thread_t &threadCtx,
                         long long eventData,
                         nvmlReturn_t nvmlReturn,
                         timelib64_t now);

    /*************************************************************************/
    /**
     * Record an Xid event for a given GPU instance
     */
    void RecordXidForGpuInstance(unsigned int gpuId,
                                 dcgmcm_update_thread_t &threadCtx,
                                 nvmlEventData_t &eventData,
                                 nvmlReturn_t nvmlReturn,
                                 timelib64_t now);

    /*************************************************************************/
    /**
     * Record an Xid event for a given compute instance
     */
    void RecordXidForComputeInstance(unsigned int gpuId,
                                     dcgmcm_update_thread_t &threadCtx,
                                     nvmlEventData_t &eventData,
                                     nvmlReturn_t nvmlReturn,
                                     timelib64_t now);

    /*************************************************************************/
    /**
     * Set the NvLink count for the GPU described by gpuInfo
     *
     * @param gpuInfo [in,out] - the struct containing the nvmlDevice handle and where we'll store the
     *                           number of NVLinks
     */
    void InitializeNvLinkCount(dcgmcm_gpu_info_t &gpuInfo);

    /*************************************************************************/
    dcgmReturn_t SetPracticalEntityInfo(dcgmcm_watch_info_t &watchInfo) const;

    /*************************************************************************/
    /*
     * Retrieves an NVML device handle for a compute instance associated with the specified entity
     *
     * @param gpuId         - the ID for the GPU
     * @param entityId      - the entity ID for the
     * @param entityGroupId - the type of entity
     *
     * @return nullptr if no GPU instance is found, the handle otherwise
     */
    nvmlDevice_t GetComputeInstanceNvmlDevice(unsigned int gpuId,
                                              dcgm_field_entity_group_t entityGroupId,
                                              unsigned int entityId);

    /*************************************************************************/
    /*
     * Iterates over the compute instances for this GPU and stores the NVML handles for them
     *
     * @param gpuInfo - the GPU we are working on
     */
    dcgmReturn_t FindAndStoreMigDeviceHandles(dcgmcm_gpu_info_t &gpuInfo);

    /*************************************************************************/
    /*
     * Finds the MIG device with the specified index for this GPU and stores it
     *
     * @param gpuInfo - the GPU we are working on
     * @param ciIndex - the index of the compute instance we're working on
     */
    dcgmReturn_t FindAndStoreDeviceHandle(dcgmcm_gpu_info_t &gpuInfo, unsigned int ciIndex);

    /*************************************************************************/
    /*
     * Stores the NVML mig device handle for the specified device if it can be found
     *
     * @param gpuInfo               - the GPU we're working on
     * @param migDevice             - the NVML mig device handle
     * @param nvmlGpuInstanceId     - the NVML id for the GPU instance
     * @param nvmlComputeInstanceId - the NVML id for the compute instance
     */
    void StoreDeviceHandle(dcgmcm_gpu_info_t &gpuInfo,
                           nvmlDevice_t migDevice,
                           unsigned int nvmlGpuInstanceId,
                           unsigned int nvmlComputeInstanceId);

    /*************************************************************************/
    /*
     * Stops the given thread with a timeout of 10s. If the thread cannot be stopped
     * in that time, it is killed.
     *
     * @param threadPtr - the DcgmThread that needs to be stopped
     */
    void StopThread(DcgmThread *threadPtr);

    /*************************************************************************/
    /*
     * Finds lost GPUs by reading the list of available GPUs from NVML and comparing to
     * the cached GPU list. Updates the status of lost GPUs to DcgmEntityStatusLost.
     */
    void UpdateLostGpus();

    /*************************************************************************/
    /*
     * Read the platform info fields using the nvmlDeviceGetPlatformInfo() API.
     */
    dcgmReturn_t ReadPlatformInfoFields(dcgmcm_update_thread_t &threadCtx,
                                        nvmlDevice_t nvmlDevice,
                                        dcgm_field_meta_p fieldMeta,
                                        timelib64_t now,
                                        timelib64_t expireTime);

    dcgmReturn_t ReadAndCacheNvLinkBer(dcgmcm_update_thread_t &threadCtx,
                                       nvmlDevice_t const nvmlDevice,
                                       unsigned short const fieldId,
                                       timelib64_t const expireTime);
};
