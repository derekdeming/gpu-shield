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
/*
 * File:   TestGroupManager.cpp
 */

#include "TestGroupManager.h"
#include <DcgmGroupManager.h>
#include <DcgmHostEngineHandler.h>
#include <DcgmSettings.h>
#include <sstream>

TestGroupManager::TestGroupManager()
{}

TestGroupManager::~TestGroupManager()
{}

/*************************************************************************/
std::string TestGroupManager::GetTag()
{
    return std::string("groupmanager");
}

/*************************************************************************/
int TestGroupManager::Init(const TestDcgmModuleInitParams &initParams)
{
    m_gpus = initParams.liveGpuIds;
    return 0;
}

/*************************************************************************/
int TestGroupManager::Run()
{
    int st;
    int Nfailed = 0;

    st = TestGroupCreation();
    if (st)
    {
        Nfailed++;
        fprintf(stderr, "TestGroupManager::TestGroupCreation FAILED with %d\n", st);
        if (st < 0)
            return -1;
    }
    else
        printf("TestGroupManager::TestGroupCreation PASSED\n");


    st = TestGroupManageGpus();
    if (st)
    {
        Nfailed++;
        fprintf(stderr, "TestGroupManager::TestGroupManageGpus FAILED with %d\n", st);
        if (st < 0)
            return -1;
    }
    else
        printf("TestGroupManager::TestGroupManageGpus PASSED\n");

    st = TestGroupReportErrOnDuplicate();
    if (st)
    {
        Nfailed++;
        fprintf(stderr, "TestGroupManager::TestGroupReportErrOnDuplicate FAILED with %d\n", st);
        if (st < 0)
            return -1;
    }
    else
        printf("TestGroupManager::TestGroupReportErrOnDuplicate PASSED\n");


    st = TestGroupGetAllGrpIds();
    if (st)
    {
        Nfailed++;
        fprintf(stderr, "TestGroupManager::TestGroupGetAllGrpIds FAILED with %d\n", st);
        if (st < 0)
            return -1;
    }
    else
    {
        printf("TestGroupManager::TestGroupGetAllGrpIds PASSED\n");
    }

    /* This test is purposely put last because it adds more GPUs to the host engine and is
       thus destructive to other tests */
    st = TestDefaultGpusAreDynamic();
    if (st)
    {
        Nfailed++;
        fprintf(stderr, "TestGroupManager::TestDefaultGpusAreDynamic FAILED with %d\n", st);
        if (st < 0)
            return -1;
    }
    else
        printf("TestGroupManager::TestDefaultGpusAreDynamic PASSED\n");

    if (Nfailed > 0)
    {
        fprintf(stderr, "TestGroupManager had %d non-fatal test failures. Failing", Nfailed);
        return 1;
    }

    st = TestGroupLimits();
    if (st)
    {
        Nfailed++;
        fprintf(stderr, "TestGroupManager::TestGroupLimits FAILED with %d\n", st);
        if (st < 0)
        {
            return -1;
        }
    }
    else
    {
        printf("TestGroupManager::TestGroupLimits PASSED\n");
    }

    return 0;
}

/*************************************************************************/
int TestGroupManager::Cleanup()
{
    return 0;
}

/*************************************************************************/
static std::unique_ptr<DcgmCacheManager> GetCacheManagerInstance(void)
{
    std::unique_ptr<DcgmCacheManager> cacheManager;

    try
    {
        cacheManager = std::make_unique<DcgmCacheManager>();
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "Got exception from DcgmCacheManager(): %s\n", e.what());
        return nullptr;
    }

    dcgmReturn_t dcgmReturn = cacheManager->Init(1, 3600.0, true);
    if (dcgmReturn != DCGM_ST_OK)
    {
        fprintf(stderr, "DcgmCacheManager::Init() failed with %s\n", errorString(dcgmReturn));
        return nullptr;
    }

    return cacheManager;
}

/*************************************************************************/
int TestGroupManager::TestGroupCreation()
{
    unsigned int groupId;
    int st, retSt = 0;

    std::unique_ptr<DcgmCacheManager> cacheManager = GetCacheManagerInstance();
    if (cacheManager == nullptr)
    {
        return -1;
    }
    std::unique_ptr<DcgmGroupManager> pDcgmGrpManager = std::make_unique<DcgmGroupManager>(cacheManager.get());

    st = pDcgmGrpManager->AddNewGroup(0, "Test1", DCGM_GROUP_DEFAULT, &groupId);
    if (DCGM_ST_OK != st)
    {
        fprintf(stderr, "pDcgmGrpManager->AddNewGroup returned %d\n", st);
        retSt = 1;
        goto CLEANUP;
    }

    st = pDcgmGrpManager->RemoveGroup(groupId);
    if (DCGM_ST_OK != st)
    {
        fprintf(stderr, "pDcgmGrpManager->RemoveGroup returned %d\n", st);
        retSt = 2;
        goto CLEANUP;
    }

CLEANUP:
    return retSt;
}

/*****************************************************************************/
int TestGroupManager::HelperOperationsOnGroup(DcgmGroupManager *pDcgmGrpManager,
                                              unsigned int groupId,
                                              std::string groupName)
{
    int st;
    std::string str;
    std::vector<dcgmGroupEntityPair_t> groupEntities;

    for (unsigned int i = 0; i < m_gpus.size(); i++)
    {
        st = pDcgmGrpManager->AddEntityToGroup(groupId, DCGM_FE_GPU, m_gpus[i]);
        if (DCGM_ST_OK != st)
        {
            fprintf(stderr, "pDcgmGrp->AddEntityToGroup returned %d\n", st);
            return 1;
        }
    }

    st = pDcgmGrpManager->GetGroupEntities(groupId, groupEntities);
    if (st != DCGM_ST_OK)
    {
        fprintf(stderr, "pDcgmGrpManager->GetGroupEntities() Failed with %d", st);
        return 2;
    }

    if (groupEntities.size() != m_gpus.size())
    {
        fprintf(
            stderr, "GPU ID size mismatch %u != %u\n", (unsigned int)groupEntities.size(), (unsigned int)m_gpus.size());
        return 2;
    }

    for (int i = m_gpus.size() - 1; i >= 0; i--)
    {
        st = pDcgmGrpManager->RemoveEntityFromGroup(0, groupId, DCGM_FE_GPU, m_gpus[i]);
        if (DCGM_ST_OK != st)
        {
            fprintf(stderr, "pDcgmGrp->RemoveEntityFromGroup returned %d\n", st);
            return 3;
        }
    }

    st = pDcgmGrpManager->RemoveEntityFromGroup(0, groupId, DCGM_FE_GPU, m_gpus[0]);
    if (DCGM_ST_BADPARAM != st)
    {
        fprintf(stderr, "pDcgmGrp->RemoveEntityFromGroup should return DCGM_ST_BADPARAM. Returned : %d\n", st);
        return 4;
    }


    str = pDcgmGrpManager->GetGroupName(0, groupId);
    if (str.compare(groupName))
    {
        fprintf(stderr, "pDcgmGrp->GetGroupName failed to match the group name\n");
        return 5;
    }

    return 0;
}

/*****************************************************************************/
int TestGroupManager::TestGroupManageGpus()
{
    int st, retSt = 0;
    std::vector<unsigned int> vecGroupIds;
    unsigned int numGroups = 20;
    std::vector<dcgmGroupEntityPair_t> groupEntities;

    std::unique_ptr<DcgmCacheManager> cacheManager = GetCacheManagerInstance();
    if (cacheManager == nullptr)
    {
        return -1;
    }
    std::unique_ptr<DcgmGroupManager> pDcgmGrpManager = std::make_unique<DcgmGroupManager>(cacheManager.get());

    for (unsigned int g = 0; g < numGroups; ++g)
    {
        std::string groupName;
        unsigned int groupId;

        std::stringstream s;
        s << g;
        groupName = "Test" + s.str();

        st = pDcgmGrpManager->AddNewGroup(0, groupName, DCGM_GROUP_EMPTY, &groupId);
        if (DCGM_ST_OK != st)
        {
            fprintf(stderr, "pDcgmGrpManager->AddNewGroup returned %d\n", st);
            retSt = 1;
            goto CLEANUP;
        }

        vecGroupIds.push_back(groupId);

        st = pDcgmGrpManager->GetGroupEntities(groupId, groupEntities);
        if (st != DCGM_ST_OK)
        {
            fprintf(stderr, "pDcgmGrpManager->GetGroupEntities returned %d\n", st);
            retSt = 3;
            goto CLEANUP;
        }

        st = HelperOperationsOnGroup(pDcgmGrpManager.get(), groupId, groupName);
        if (DCGM_ST_OK != st)
        {
            retSt = 4;
            goto CLEANUP;
        }
    }

    for (unsigned int g = 0; g < numGroups; ++g)
    {
        st = pDcgmGrpManager->RemoveGroup(vecGroupIds[g]);
        if (DCGM_ST_OK != st)
        {
            fprintf(stderr, "pDcgmGrpManager->RemoveGroup returned %d\n", st);
            retSt = 5;
            goto CLEANUP;
        }
    }

CLEANUP:
    return retSt;
}

/*****************************************************************************/
int TestGroupManager::TestGroupReportErrOnDuplicate()
{
    int st, retSt = 0;
    unsigned int groupId;

    std::unique_ptr<DcgmCacheManager> cacheManager = GetCacheManagerInstance();
    if (cacheManager == nullptr)
    {
        return -1;
    }
    std::unique_ptr<DcgmGroupManager> pDcgmGrpManager = std::make_unique<DcgmGroupManager>(cacheManager.get());

    st = pDcgmGrpManager->AddNewGroup(0, "Test1", DCGM_GROUP_EMPTY, &groupId);
    if (DCGM_ST_OK != st)
    {
        fprintf(stderr, "pDcgmGrpManager->AddNewGroup returned %d\n", st);
        retSt = 1;
        goto CLEANUP;
    }

    st = pDcgmGrpManager->AddEntityToGroup(groupId, DCGM_FE_GPU, m_gpus[0]);
    if (DCGM_ST_OK != st)
    {
        fprintf(stderr, "pDcgmGrp->AddEntityToGroup returned %d\n", st);
        retSt = 4;
        goto CLEANUP;
    }

    st = pDcgmGrpManager->AddEntityToGroup(groupId, DCGM_FE_GPU, m_gpus[0]);
    if (DCGM_ST_BADPARAM != st)
    {
        fprintf(stderr, "pDcgmGrp->AddEntityToGroup must fail for duplicate entry %d\n", st);
        retSt = 5;
        goto CLEANUP;
    }

    st = pDcgmGrpManager->RemoveGroup(groupId);
    if (DCGM_ST_OK != st)
    {
        fprintf(stderr, "pDcgmGrpManager->RemoveGroup returned %d\n", st);
        retSt = 6;
        goto CLEANUP;
    }

CLEANUP:
    return retSt;
}

int TestGroupManager::TestGroupGetAllGrpIds()
{
    int st, retSt = 0;
    unsigned int groupId;
    unsigned int index;
    unsigned int groupIdList[DCGM_MAX_NUM_GROUPS];
    unsigned int count;

    std::unique_ptr<DcgmCacheManager> cacheManager = GetCacheManagerInstance();
    if (cacheManager == nullptr)
    {
        return -1;
    }
    std::unique_ptr<DcgmGroupManager> pDcgmGrpManager = std::make_unique<DcgmGroupManager>(cacheManager.get());

    unsigned int max_groups = 10;
    for (index = 0; index < max_groups; index++)
    {
        st = pDcgmGrpManager->AddNewGroup(0, "Test", DCGM_GROUP_EMPTY, &groupId);
        if (DCGM_ST_OK != st)
        {
            fprintf(stderr, "pDcgmGrpManager->AddNewGroup returned %d\n", st);
            retSt = 1;
            goto CLEANUP;
        }
    }

    retSt = pDcgmGrpManager->GetAllGroupIds(0, groupIdList, &count);
    if (0 != retSt)
    {
        retSt = 2;
        goto CLEANUP;
    }

    if (count != max_groups + 2)
    { // +2 for the default group
        retSt = 3;
        goto CLEANUP;
    }

    retSt = pDcgmGrpManager->RemoveAllGroupsForConnection(0);
    if (0 != retSt)
    {
        retSt = 4;
        goto CLEANUP;
    }

CLEANUP:
    return retSt;
}

/*************************************************************************/
int TestGroupManager::TestDefaultGpusAreDynamic()
{
    unsigned int groupId;
    bool found = false;
    int retSt  = 0;
    unsigned int i;
    dcgmReturn_t dcgmReturn;
    unsigned int fakeEntityId;
    size_t beforeSize, afterSize;
    std::vector<dcgmGroupEntityPair_t> entities;

    /* We need to use the host engine handler directly or we'll be injecting
       entities into the wrong cache manager */
    DcgmHostEngineHandler *heHandler = DcgmHostEngineHandler::Instance();
    DcgmCacheManager *cacheManager   = heHandler->GetCacheManager();
    DcgmGroupManager *groupManager   = heHandler->GetGroupManager();

    groupId    = groupManager->GetAllGpusGroup();
    dcgmReturn = groupManager->GetGroupEntities(groupId, entities);
    if (dcgmReturn != DCGM_ST_OK)
    {
        fprintf(stderr, "Got error %d from GetGroupEntities()\n", dcgmReturn);
        retSt = 100;
        goto CLEANUP;
    }

    beforeSize = entities.size();

    if (beforeSize >= DCGM_MAX_NUM_DEVICES)
    {
        printf("TestGroupDefaultsAreDynamic Skipping test due to already having %d GPUs\n", (int)beforeSize);
        retSt = 0;
        goto CLEANUP;
    }

    /* Add a fake GPU and make sure it appears in the entity list */
    fakeEntityId = cacheManager->AddFakeGpu();

    dcgmReturn = groupManager->GetGroupEntities(groupId, entities);
    if (dcgmReturn != DCGM_ST_OK)
    {
        fprintf(stderr, "Got error %d from GetGroupEntities()\n", dcgmReturn);
        retSt = 200;
        goto CLEANUP;
    }

    afterSize = entities.size();

    if (afterSize != beforeSize + 1)
    {
        fprintf(stderr, "Expected afterSize %d to be beforeSize %d + 1\n", (int)afterSize, (int)beforeSize);
        retSt = 300;
        goto CLEANUP;
    }

    found = false;
    for (i = 0; i < entities.size(); i++)
    {
        if (fakeEntityId == entities[i].entityId && entities[i].entityGroupId == DCGM_FE_GPU)
        {
            found = true;
            break;
        }
    }

    if (!found)
    {
        fprintf(stderr, "Unable to find GPU %u in list of %d", fakeEntityId, (int)entities.size());
        retSt = 400;
        goto CLEANUP;
    }

CLEANUP:
    /* We used to restart the host engine here to clear injected GPUs, but that's handled by
       GetConfig() returning config.restartEngineAfter = true now */
    return retSt;
}

/*************************************************************************/
void TestGroupManager::GetConfig(TestDcgmModuleConfig &config)
{
    config.restartEngineBefore = false;
    config.restartEngineAfter  = true; /* TestDefaultGpusAreDynamic() is destructive */
}

/*************************************************************************/

#define CHECK(x, fmt, ...)                                                        \
    do                                                                            \
    {                                                                             \
        if (!(x))                                                                 \
        {                                                                         \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #x); \
            fprintf(stderr, fmt __VA_OPT__(, ) __VA_ARGS__);                      \
            return -1;                                                            \
        }                                                                         \
    } while (0)

/*************************************************************************/

int TestGroupManager::TestGroupLimits()
{
    int st, retSt = 0;
    unsigned int groupId;
    unsigned int index;
    unsigned int groupIdList[DCGM_MAX_NUM_GROUPS];
    unsigned int count;

    std::unique_ptr<DcgmCacheManager> cacheManager = GetCacheManagerInstance();
    CHECK(cacheManager != nullptr, "expected cacheManager != nullptr\n");

    std::unique_ptr<DcgmGroupManager> pDcgmGrpManager = std::make_unique<DcgmGroupManager>(cacheManager.get());
    CHECK(pDcgmGrpManager != nullptr, "expected pDcgmGrpManager != nullptr\n");

    /* Verify default groups */
    retSt = pDcgmGrpManager->GetAllGroupIds(0, groupIdList, &count);
    CHECK(retSt == 0, "expected st %d, got %d\n", 0, retSt);
    CHECK(count == 2, "expected default group count %d, got %d\n", 2, count);

    /* Test group maximum */

    for (index = 2; index < DCGM_MAX_NUM_GROUPS; index++)
    {
        st = pDcgmGrpManager->AddNewGroup(0, "Test", DCGM_GROUP_EMPTY, &groupId);
        CHECK(st == DCGM_ST_OK, "expected AddNewGroup[%d] st %d, got %d\n", index, DCGM_ST_OK, st);
    }

    retSt = pDcgmGrpManager->GetAllGroupIds(0, groupIdList, &count);
    CHECK(retSt == 0, "expected GetAllGroupIds st %d, got %d\n", 0, retSt);
    CHECK(count == 64, "expected count %d, got %d\n", 64, count);

    for (index = 2; index < DCGM_MAX_NUM_GROUPS; index++)
    {
        std::vector<dcgmGroupEntityPair_t> entities {};
        st = pDcgmGrpManager->GetGroupEntities(index, entities);
        CHECK(st == DCGM_ST_OK, "Unable to retrieve entities for groupId %d", index);
        CHECK(entities.size() == 0, "Got %ld entities for groupId %d, expected %d\n", entities.size(), index, 0);
        std::string groupName = pDcgmGrpManager->GetGroupName(DCGM_CONNECTION_ID_NONE, index);
        CHECK(groupName == std::string_view("Test"),
              "Got groupName \"%s\" for groupId %d, expected \"Test\"",
              groupName.c_str(),
              index);
    }

    st = pDcgmGrpManager->AddNewGroup(0, "Test", DCGM_GROUP_EMPTY, &groupId);
    CHECK(st == DCGM_ST_MAX_LIMIT, "expected AddNewGroup() st %d, got %d\n", DCGM_ST_MAX_LIMIT, st);

    retSt = pDcgmGrpManager->RemoveAllGroupsForConnection(0);
    CHECK(retSt == 0, "expected RemoveAllGroupsForConnection st %d, got %d\n", 0, retSt);
    return 0;
}