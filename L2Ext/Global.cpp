#include "StdAfx.h"
#include "CursedWeaponSystem.h"
#include "DB.h"
#include "TerritoryData.h"

//Global variables
SPLASH g_SplashScreen;
CHookManager g_HookManager;
CMTRandom g_MTRandom;
CConfig* CConfig::Instance = NULL;
CConfig g_Config;
CL2Time g_L2Time;
CSkillDB g_SkillDB;
CDB g_DB;
CPledgeDB g_PledgeDB;
CResidenceDBEx g_ResidenceDBEx;
CSkillDBEx g_SkillDBEx;
CEnchantedSet g_EnchantedSet;
CTeamContainer g_TeamContainer;
CItemReuseManager g_ItemReuseManager;
CSkillReuseManager g_SkillReuseManager;
CSpiritSystem g_SpiritSystem;
CEraSystem g_EraSystem;
CTerritoryChecker g_TerritoryChecker;
CKillDeathStat g_KillDeathStat;
CAdminSocket g_AdminSocket;
CTaskHandler g_TaskHandler;
CItemDBEx g_ItemDBEx;
CResidenceDB g_ResidenceDB;
CWorld g_World;
CPartyWaitingList g_PartyWaitingList;
CNpcMaker g_NpcMaker;
CSkillEnchantDB g_SkillEnchantDB;
CDoorDB g_DoorDB;
CCursedWeaponSystem g_CursedWeaponSystem;

