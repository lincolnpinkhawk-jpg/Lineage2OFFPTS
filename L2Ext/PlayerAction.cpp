#include "StdAfx.h"
#include "PlayerAction.h"
#include "VIPSystem.h"
#include "ClanSys.h"
#include "TerritoryData.h"
#include "TvT.h"
#include "OfflineShop.h"
#include "AIO.h"
#include "BuildCmdHandler.h"
#include "PrivateStore.h"
#include "CursedWeaponSystem.h"
#include "OlympiadSystem.h"
#include "Augmentation.h"
#include "SocketDB.h"
#include "DB.h"
#include "AccountDB.h"
#include "VoteReward.h"
#include "AutoLearn.h"
#include "AutoAnnounce.h"
#include "HTMLCacheManager.h"
#include "DnN.h"
#include "FractionSystem.h"
#include "ItemDelivery.h"
#include "UserCache.h"
#include "HeroSystem.h"
#include "AutoLoot.h"
#include "SchemeBuffer.h"
#include "DeathPenalty.h"
#include "OlympiadField.h"
#include "HtmlFilter.h"
#include "InfinityShot.h"
#include "DuelSystem.h"
#include "HTMLCache.h"
#include "ArmorPenalty.h"
#include "Auction.h"
#include "Wedding.h"
#include "CliExt.h"
#include "ItemAutoConsume.h"
#include "CharacterLock.h"
#include "DailyPvP.h"
#include "SubStack.h"
#include "SpawnProtection.h"
#include "L2NetworkVote.h"
#include "VisualArmor.h"
#include "Rebirth.h"
#include "GradePenalty.h"
#include "RecipeManager.h"
#include "ObjectDB.h"
#include "PvPAnnounce.h"
#include "Captcha.h"
#include "JailSystem.h"
#include "LureProtection.h"
#include "FlagSystem.h"
#include "Antibot.h"
#include "HappyHours.h"
#include "OfflineShopRestore.h"
#include "EventStats.h"
#include "ChampionNpc.h"
#include "OfflineSocketDB.h"
#include "IndividualVote.h"

#include "Hair2Slot.h"
#include "Achivments.h"
#include "PvPEvents.h"
#include "RatesDinamicos.h"
#include "Championship.h"


extern BOOL g_AttackWarWithoutCTRL;
extern BOOL g_ValidateAcquiredSkills;
extern list<int> g_OlympiadForbiddenItemList;
extern vector<UINT> g_OlympiadForbiddenItemGrade;
extern INT32 g_OlympiadMaxAllowedWeaponEnchant;
extern INT32 g_OlympiadMaxAllowedArmorEnchant;
extern map<INT32, DWORD> g_ItemNicknameColor;
extern map<INT32, DWORD> g_ItemNicknameColor2;
extern map<INT32, DWORD> g_ItemTitleColor;
extern OlympiadPeriod g_OlympiadPeriod[7][2];
extern BOOL g_ShowInventoryOnEnterWorld;
extern BOOL m_BuilderSkills;
extern BOOL g_ValidateStackableItems;
extern BOOL g_DisablePets;
extern BOOL g_ShowEnterWorldHtml;
extern INT32 g_MaxPartyLevelRange;
extern BOOL g_IsDistributingExpSp[32];
extern CCreature* g_DistributingCreature[32];
extern double g_PartyExpRate;
extern BOOL g_CustomAbnormalInfoPacket;
extern BOOL g_OlympiadStopActionOnFightStart;
extern BOOL g_OlympiadRestoreStatsOnFightStart;
extern UINT g_SaveAbnormalsIntervalTime;
extern CCreature* g_NpcKiller[26];
extern CNPC* g_KilledNpc[26];
extern BOOL g_SpiritShotExtension;
extern BOOL g_SaveInstancesOnDB;

vector<INT32> g_InfinityArrow;

double g_ExpCurve[85];

extern BOOL g_MiAutoSkill;
extern BOOL g_AnnounceSubClass;
extern tstring g_AnnounceSubClassMsg1;
extern tstring g_AnnounceSubClassMsg2;
extern tstring g_AnnounceSubClassMsg3;

extern INT32 m_TerminarPersonajeRewardId;
extern INT32 m_TerminarPersonajeRewardAmount;

extern wstring g_MensajeEnterWorldServer;

extern BOOL g_NoDropPlayerOnDie;
extern BOOL g_Config_GM_Login_Undying;
extern BOOL g_Config_GM_Login_UnHide;

extern BOOL OlympiadInstanceEnable;
extern UINT OlympiadInstanceCount;

extern INT32 g_MiAutoSkillMaxLevel;

extern BOOL g_achiv;

extern BOOL g_NoPermitirDosTanques;


extern INT32 g_MaximoDeTercerasLogout;


extern BOOL BienvenidoNuevoPersonaje;
extern wstring BienvenidoNuevoPersonajeMsg;
extern vector<wstring> Hwids;

void SendSkillReuseMsg(CUserSocket *pSocket, const char* format, BYTE opCode, DWORD msgId, DWORD varCount, DWORD varType, DWORD skillId, DWORD skillLevel)
{
	if(User *pUser = pSocket->GetUser())
	{
		if(pUser->olympiadUser.IsInside())
		{
			DWORD secLeft = pUser->GetSkillReuse(skillId) - GetTickCount();
			secLeft /= 1000;
			if(secLeft > 0)
			{	//There are $s1 second(s) remaining in $s2's re-use time.
				CSystemMessage msg(2415);
				msg.AddNumber(secLeft);
				msg.AddSkill(skillId, skillLevel);
				pUser->SendSystemMessage(&msg);
				return;
			}
		}
	}
	pSocket->Send(format, opCode, msgId, varCount, varType, skillId, skillLevel);
}

void PlayerAction::Initialize()
{
	TCHAR temp[8190] = { 0 };
	if(GetPrivateProfileString(_T("L2Server"), _T("InfinityArrowList"), 0, temp, 8190, g_ConfigFile))
	{
		wstringstream itemStream(temp);
		int itemId = 0;
		while(itemStream >> itemId)
		{
			g_InfinityArrow.push_back(itemId);
		}
	}

	for(UINT n=0;n<85;n++)
	{
		g_ExpCurve[n] = 1.0;
	}

	for(int n=0;n<85;n++)
	{
		wstringstream key;
		key << L"ExpCurveParam_" << n;
		g_ExpCurve[n] = GetPrivateProfileDouble(_T("Features"), key.str().c_str(), 1.0, g_ConfigFile);
	}
	g_HookManager.WriteCall(0x70A821, COlympiadEntry_RemoveEntry, 0);
	g_HookManager.WriteCall(0x70A996, COlympiadEntry_RemoveEntry, 0);

	g_HookManager.WriteCall(0x70EAD9, COlympiadEntry_AddEntry, 0);
	g_HookManager.WriteCall(0x70E909, COlympiadEntry_AddEntry, 0);
	g_HookManager.WriteCall(0x70DE2E, COlympiadEntry_AddEntry, 0);
	g_HookManager.WriteCall(0x70DDB6, COlympiadEntry_AddEntry, 0);
	g_HookManager.WriteCall(0x70DC09, COlympiadEntry_AddEntry, 0);
	g_HookManager.WriteCall(0x70DB8F, COlympiadEntry_AddEntry, 0);
	g_HookManager.WriteCall(0x70D9D4, COlympiadEntry_AddEntry, 0);
	g_HookManager.WriteCall(0x70D95F, COlympiadEntry_AddEntry, 0);


	g_HookManager.WriteCall( 0x57602E, OnEnterWorld, 0);
	g_HookManager.WriteCall( 0x850006, OnLeaveWorld, 0);
	g_HookManager.WriteMemoryDWORD(0xA87760, (DWORD)OnDie);
	g_HookManager.WriteCall( 0x581B1E, OnPickUpItem, 0);
	g_HookManager.WriteCall( 0x553DA8, OnAddItemToInventory, 0);
	g_HookManager.WriteCall( 0x553587, OnAddItemToInventory, 0);
	g_HookManager.WriteCall( 0x553860, OnAddItemToInventory, 0);
	g_HookManager.WriteMemoryDWORD(0xA876D0, (DWORD)UseItem);
	g_HookManager.WriteMemoryDWORD(0xA876C8, (DWORD)UnequipItem);
	g_HookManager.WriteCall( 0x70D185, RegisterInOlympiad, 0);
	
	g_HookManager.WriteCall( 0x53FEAF, OnChangeSubjobEnd, 0);
	g_HookManager.WriteCall( 0x56FE7A, OnCreateSubjobEnd, 0);
	g_HookManager.WriteCall( 0x5715EE, OnChangeSubjobEnd, 0);

	g_HookManager.WriteMemoryDWORD(0xA876E0, (DWORD)OnDropItem);
	g_HookManager.WriteMemoryDWORD(0xA87530, (DWORD)OnPvPFlag); //PvP Flag Fix -> FACTION

	g_HookManager.WriteCall( 0x513BDE, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x4D8959, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x800C71, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x80FFC5, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x8102D5, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x8107ED, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x853000, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x852C72, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x8536F1, OnGetRelationTo, 0);
	g_HookManager.WriteCall( 0x705F2C, OnOlympiadEscaping, 0);
	g_HookManager.WriteCall( 0x703B14, OnOlympiadFinishMatch, 0);
	g_HookManager.WriteCall( 0x7000B9, OnEnteringOlympiadStadion, 0);
	g_HookManager.WriteCall( 0x8465D3, OnUpdateHP, 0);
	g_HookManager.WriteCall( 0x8000B2, OnSendETCBuffStatusInfo, 0);
	g_HookManager.WriteCall( 0x7032AC, OnOlympiadStartMatch, 0);
	g_HookManager.WriteMemoryDWORD(0xA87758, (DWORD)OnTeleportToLocation);
	g_HookManager.WriteMemoryDWORD(0xA876B8, (DWORD)OnEquipItem);
	g_HookManager.WriteCall( 0x81E607, OnDieLooseExp, 0);
	g_HookManager.WriteCall( 0x81E667, OnDieLooseExp, 0);
	g_HookManager.WriteCall( 0x81E6D3, OnDieLooseExp, 0);
	g_HookManager.WriteCall( 0x81E88E, OnDieDropItem, 0);
	g_HookManager.WriteCall( 0x512844, IncreaseKarma, 0);
	g_HookManager.WriteMemoryDWORD(0xA87230, (DWORD)OnTimerExpired);
	g_HookManager.WriteCall(0x53A900, SaveCharacterInfo, 1);
	g_HookManager.WriteCall(0x572095, LoadItemsPacket, 0);

	g_HookManager.WriteCall(0x436CCA, ObserverStart, 0);
	g_HookManager.WriteCall(0x44A7BF, ObserverStart, 0);
	g_HookManager.WriteCall(0x895A32, ObserverStart, 0);

	g_HookManager.WriteCall(0x449D48, ObserverEnd, 0);
	g_HookManager.WriteCall(0x869361, ObserverEnd, 0);
	g_HookManager.WriteCall(0x845ED3, ObserverEnd, 0);
	g_HookManager.WriteCall(0x6FF350, ObserverEnd, 0);
	g_HookManager.WriteCall(0x6FF3BB, ObserverEnd, 0);

	g_HookManager.WriteCall(0x467C61, OnChangeSubjobBegin, 0);
	g_HookManager.WriteCall(0x467E98, OnChangeSubjobBegin, 0);
	g_HookManager.WriteCall(0x467F8F, OnChangeSubjobBegin, 0);
	g_HookManager.WriteCall(0x6E3912, OnChangeSubjobBegin, 0);
	g_HookManager.WriteCall(0x6E3410, OnChangeSubjobBegin, 0);
	g_HookManager.WriteCall(0x6E3D3F, OnChangeSubjobBegin, 0);

	g_HookManager.WriteCall(0x6F743F, OnSendXPnSP, 0);
	g_HookManager.WriteCall(0x6F750D, OnSendXPnSP, 0);
	g_HookManager.WriteCall(0x6F8F3C, OnSendXPnSP, 0);

	g_HookManager.WriteMemoryDWORD(0xA874C8, (DWORD)PlayerAction::OnClassChange);

	g_HookManager.WriteMemoryDWORD(0xA878D8, (DWORD)PlayerAction::OnHear);

	g_HookManager.WriteCall(0x6B3487, SendSkillReuseMsg, 0);
	g_HookManager.WriteCall(0x6B56F5, SendSkillReuseMsg, 0);

	g_HookManager.WriteMemoryDWORD(0xA87730, (DWORD)PlayerAction::OnDeleteItemInInventoryBeforeCommit, 0);

	g_HookManager.WriteCall(0x8A2E58, PlayerAction::DeleteShipTicket, 4);

	g_HookManager.WriteCall(0x80F48A, PlayerAction::TradeCancelled, 0);	//in User::TradeCancel
	g_HookManager.WriteCall(0x7CDB4B, PlayerAction::SummonPet, 0);
	if(g_CustomAbnormalInfoPacket)
	{
		g_HookManager.WriteMemoryDWORD(0xA87900, (DWORD)PlayerAction::SendAbnormalStatusInfo);
	}

	g_HookManager.WriteCall(0x411D0F, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x437A10, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x43800A, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x4FB072, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x550E31, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x551AC8, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x5F2C2B, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x6D9BEF, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x6E589A, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x6ED0D7, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x6ED6CE, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x710098, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x711D95, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x7705DD, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x797140, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x797249, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x797514, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x894538, PlayerAction::ShowHTML);
	g_HookManager.WriteCall(0x8947B1, PlayerAction::ShowHTML);

	g_HookManager.WriteCall(0x60DFBC, PlayerAction::NpcHtmlSender);

	g_HookManager.WriteCall(0x6DD674, PlayerAction::ShowTutorialPage);	//ShowTutorialPage
	g_HookManager.WriteCall(0x8718C4, PlayerAction::ShowTutorialPage);	//TutorialLinkHTML
	g_HookManager.WriteCall(0x464D1E, PlayerAction::ShowTutorialPage);	//BuilderCmd_show_tutorial_html

	g_HookManager.WriteCall(0x825356, PlayerAction::OnRestartSendSaveCharacterInfo);
	g_HookManager.WriteCall(0x7137C6, PlayerAction::ShowCommunityBoard);
	g_HookManager.WriteCall(0x7138EF, PlayerAction::ShowCommunityBoard);
	g_HookManager.WriteCall(0x713A10, PlayerAction::ShowCommunityBoard);
	g_HookManager.WriteCall(0x713B26, PlayerAction::ShowCommunityBoard);

	g_HookManager.WriteCall(0x76A5BF, PlayerAction::OnTakeWithdrawPenalty);
	g_HookManager.NopMemory(0x846197, 8);

	g_HookManager.WriteCall(0x5128DF, PlayerAction::DBIncreaseUserDuelCount);
	g_HookManager.WriteMemoryDWORD(0xA8EEF0, (DWORD)PlayerAction::CUserSocket_TimerExpired);

	g_HookManager.WriteMemoryDWORD(0xA877C8, (DWORD)PlayerAction::OnAction);

	g_HookManager.WriteMemoryDWORD(0xA87690, (DWORD)PlayerAction::OnBroadcastCombatModeStart);

	g_HookManager.WriteCall(0x467FB6, PlayerAction::OnDBRequestRenewSubjob);
	g_HookManager.WriteCall(0x6E3DB4, PlayerAction::OnDBRequestRenewSubjob);

	g_HookManager.WriteCall(0x7FDCF4, PlayerAction::OnValidateCpRegen);

	g_HookManager.WriteCall(0x866573, PlayerAction::OnSendSkillAcquireList);

	g_HookManager.WriteCall(0x773FFC, PlayerAction::OnRecipeMakeItem, 0);


	//g_HookManager.WriteMemoryDWORD(0x84D808, 1261);
	//g_HookManager.WriteMemoryBYTE(0x84D808, 0x58); //neophron interface crack
}

void PlayerAction::OnRecipeMakeItem(PVOID instancePtr, User *pUser, UINT recipeId, UINT result, UINT ingrCount, UINT buffLen, PCHAR buffer)
{
	CTL;
	const unsigned char *tempPtr = (const unsigned char*)buffer;
	if(result > 0)
	{
		if(CRecipeManager::Get().Enabled())
		{
			int systemMessageId = 0;
			ItemReq newItem;
			if(CRecipeManager::Get().OnCraft(pUser, recipeId, newItem, systemMessageId))
			{
				if(CItem *pTemplate = g_ObjectDB.GetTemplateObject(newItem.itemId)->SafeCastItem())
				{
					UINT newItemCount = 0;
					for(UINT n=0;n<ingrCount;n++)
					{
						INT32 itemClassId, amount, stackableType, param4, param5;
						tempPtr = Disassemble(tempPtr, "ddddd", &itemClassId, &amount, &stackableType, &param4, &param5);
					//	g_Log.Add(CLog::Blue, "[%s] recipe[%d] ingrCount[%d] cur[%d], param1[%d] param2[%d] stackableType[%d] param4[%d] param5[%d]", __FUNCTION__, recipeId, ingrCount, n, itemClassId, amount, stackableType, param4, param5);
						if(amount > 0)
						{
							//replace this item
							if(newItem.amount > 1 && pTemplate->pSID->nConsumeType == ConsumeNormal)
							{
								//simple replace
								PINT32 paramPtr = (PINT32)&tempPtr[-20];
								(*paramPtr) = newItem.itemId;
								(*(paramPtr+1)) = 1;
								(*(paramPtr+2)) = pTemplate->pSID->nConsumeType;
								for(int i = 1; i < newItem.amount; i++)
								{
									buffLen += Assemble(&buffer[buffLen], (8190 - buffLen), "ddddd", newItem.itemId, 1, ConsumeNormal, 0, 0);
									newItemCount++;
								}
							}else
							{
								//simple replace
								PINT32 paramPtr = (PINT32)&tempPtr[-20];
								(*paramPtr) = newItem.itemId;
								(*(paramPtr+1)) = newItem.amount;
								(*(paramPtr+2)) = pTemplate->pSID->nConsumeType;
								(*(paramPtr+3)) = 0;
								(*(paramPtr+4)) = 0;
							}
							break;
						}
					}
					if(newItemCount)
						ingrCount+=newItemCount;

					if(systemMessageId)
						pUser->pSocket->SendSystemMessage(systemMessageId);
				}
			}
		}
	}

	typedef void(*f)(PVOID, User*, UINT, UINT, UINT, UINT, PCHAR);
	f(0x52AD40L)(instancePtr, pUser, recipeId, result, ingrCount, buffLen, buffer);
}

void PlayerAction::OnSendSkillAcquireList(User *pUser, UINT type)
{
	guard;

	pUser->pED->skillMasterFlag = 0;
	typedef void(*f)(User*, UINT);
	f(0x84E5E0L)(pUser, type);

	unguard;
}

bool PlayerAction::OnValidateCpRegen(User *pUser)
{
	guard;

	bool ret = false;

	typedef bool (*f)(User*);
	ret = f(0x4DBBD0L)(pUser);

	//apply our p_regen_cp
	if(pUser->pSD->nIsPC)
	{
		pUser->pSD->cpRegen *= pUser->pSD->pExData->SkillMod.regenCpMul;
		pUser->pSD->cpRegen += pUser->pSD->pExData->SkillMod.regenCpAdd;
	//	g_Log.Add(CLog::Blue, "[%s] [%f] [%f] total regen[%f]", __FUNCTION__, pUser->pSD->pExData->SkillMod.regenCpMul, pUser->pSD->pExData->SkillMod.regenCpAdd, pUser->pSD->cpRegen);

	}


	unguard;
	return ret;
}

void PlayerAction::OnDBRequestRenewSubjob(PVOID pInstance, User *pUser, UINT subjobId, UINT newClass, bool byBuilder, int npcIndex, int userIndex)
{
	guard;

	if(g_SubStack.IsEnabled())
	{
		if(subjobId < 4)
		{
			//check player substack
			if(pUser->pED->subStackInfo.classId[subjobId][0] != UINT_MAX)
			{
				//clear it
				pUser->pED->subStackInfo.classId[subjobId][0] = UINT_MAX;
				pUser->pED->subStackInfo.classId[subjobId][1] = UINT_MAX;
				g_DB.RequestSaveSubStack(pUser->nDBID, subjobId, UINT_MAX, UINT_MAX);
				g_Logger.Add(L"User[%s] removed subjob[%d] - deleting stacks!", pUser->pSD->wszName, subjobId);
			}
		}
	}

	typedef void(*f)(PVOID, User*, UINT, UINT, bool, int, int);
	f(0x533B60L)(pInstance, pUser, subjobId, newClass, byBuilder, npcIndex, userIndex);

	unguard;
}

void PlayerAction::OnBroadcastCombatModeStart(User *pUser)
{
	guard;

	pUser->pED->broadcastCombatModeTimestamp = time(0) + 3;
	typedef void(*f)(User*);
	f(0x4EBA50L)(pUser);

	unguard;
}

void PlayerAction::OnAction(User *pUser, CObject *pTarget, bool force, bool notMove)
{
//	g_Log.Add(CLog::Blue, "[%s] User[%s] force[%d] notMove[%d]", __FUNCTION__, pUser->pSD->wszName, force, notMove);
	typedef void (*f)(User*, CObject*, bool, bool);
	f(0x4E46C0L)(pUser, pTarget, force, notMove);
}

void PlayerAction::CUserSocket_TimerExpired(CUserSocket *pSocket, UINT id)
{
	guard;

//	g_Log.Add(CLog::Blue, "[%s] id[%d] s1[%d]s2[%d] [%d]", __FUNCTION__, id, pSocket->state, pSocket->socketStatus, GetTickCount());

	typedef void(*f)(CUserSocket*, UINT);
	f(0x877BA0L)(pSocket, id);

	if(pSocket->socketStatus != 2)
	{
		if(g_CliExt.IsEnabled())
			g_CliExt.TimerExpired(pSocket);
		else
		{
			if(pSocket->pED->longHWID.IsNull())
			{
	//			CHAR buffEx[8190];
	//			int lenEx = Assemble(buffEx, 8190, "cd", 0x87, 0x02);
	//			pSocket->Send("b", lenEx, buffEx);
			}

			if(pSocket->pED->md5Checksum[0] == 0 && pSocket->pED->md5Checksum[1] != 1)
			{
	//			pSocket->pED->md5Checksum[1] = 1;
	//			CHAR buffEx[8190];
	//			int lenEx = Assemble(buffEx, 8190, "cd", 0x87, 12, GetTickCount());
	//			pSocket->Send("b", lenEx, buffEx);
			}
		}
	}

	unguard;
}

void PlayerAction::DBIncreaseUserDuelCount(LPVOID pInstance, UINT charId)
{
	guard;
	if(charId > 0)
	{
		typedef void(*f)(LPVOID, UINT);
		f(0x52A9F0L)(pInstance, charId);
	}
	unguard;
}

void PlayerAction::OnTakeWithdrawPenalty(User *pUser)
{
	guard;
	if(pUser->pSD->nPledgeType != CPledge::ACADEMY)
	{
		typedef void(*f)(User*);
		f(0x803BE0L)(pUser);
	}
	unguard;
}

void PlayerAction::OnRestartSendSaveCharacterInfo(LPVOID lpInstance, User *pUser, UINT param1, bool param2)
{
	guard;
	typedef void(*f)(LPVOID, User*, UINT, bool);
	f(0x53A250L)(lpInstance, pUser, 1, true);
	unguard;
}

void PlayerAction::ShowTutorialPage(CUserSocket *pSocket, const char* format, BYTE opCode, const WCHAR* wHtml)
{
	guard;
	if(User *pUser = pSocket->pUser->SafeCastUser())
	{
		g_HtmlFilter.OnSendHtml(pUser, L"ShowTutorialPage.htm", wHtml, -1);
		pSocket->Send(format, opCode, wHtml);
	}
	unguard;
}

void PlayerAction::NpcHtmlSender(CUserSocket *pSocket, const char* format, BYTE opCode, UINT talkTargetId, const WCHAR* wHtml)
{
	guard;
	if(User *pUser = pSocket->pUser->SafeCastUser())
	{
		g_HtmlFilter.OnSendHtml(pUser, L"NpcHtmlSender.htm", wHtml, 0);
		pSocket->Send(format, opCode, talkTargetId, wHtml);
	}
	unguard;
}

void PlayerAction::ShowCommunityBoard(CUserSocket *pSocket, const char* format, BYTE opCode, BYTE param1, const WCHAR* wBypass2, const WCHAR* wBypass3, const WCHAR* wBypass4, const WCHAR* wBypass5, const WCHAR* wBypass6, const WCHAR* wBypass7, const WCHAR* wBypass8, const WCHAR* wBypass9, const WCHAR* wHtml)
{
	guard;

	if(g_HtmlFilter.IsEnabled())
	{
		wstringstream dataStream;
		dataStream << wBypass2 << endl << wBypass3 << endl << wBypass4 << endl << wBypass5 << endl << wBypass6 << endl << wBypass7 << endl << wBypass8 << endl << wBypass9 << endl << wHtml << endl;
		g_HtmlFilter.OnSendHtml(pSocket->pUser, L"community_board.htm", dataStream.str().c_str(), 0);
	}

	pSocket->Send(format, opCode, param1, wBypass2, wBypass3, wBypass4, wBypass5, wBypass6, wBypass7, wBypass8, wBypass9, wHtml);

	unguard;
}

void PlayerAction::ShowHTML(User *pUser, const WCHAR *wName, const WCHAR *wHtml, UINT itemClassId)
{
	guard;
	if( pUser->SafeCastUser())
	{
		g_HtmlFilter.OnSendHtml(pUser, wName, wHtml, itemClassId);

		typedef void (*f)(User*, const WCHAR*, const WCHAR*, UINT);
		f(0x80A060L)(pUser, wName, wHtml, itemClassId);
	}

	unguard;
}

void PlayerAction::SendAbnormalStatusInfo(User *pUser)
{
	guard;
	pUser->SendAbnormalStatusInfo();
	unguard;
}

void PlayerAction::SummonPet(User *pUser, CItem *pPetCollar)
{
	guard;

	if(!g_DisablePets)
	{
		if(pUser->ValidUser())
		{
			if(pUser->IsNowTrade())
			{
				pUser->TradeCancel();
			}
		}

		typedef void(*f)(User*, CItem*);
		f(0x8169F0L)(pUser, pPetCollar);
	}else
	{
		pUser->pSocket->SendSystemMessage(L"Pet System is temporary disabled and you cannot summon any pet.");
	}

	unguard;
}

void PlayerAction::TradeCancelled(CTrade *pTrade, User *pTrader)
{
	guard;

	UINT trader1Id = pTrade->traderId[0];
	UINT trader2Id = pTrade->traderId[1];

	typedef void(*f)(CTrade*, User*);
	f(0x7F5330L)(pTrade, pTrader);

	if(User *p1 = User::GetUserBySID(&trader1Id))
	{
		p1->SetItemListChanged();
	}
	
	if(User *p1 = User::GetUserBySID(&trader2Id))
	{
		p1->SetItemListChanged();
	}
	unguard;
}

bool PlayerAction::OnTeleportToLocation(User *pUser, int nX, int nY, int nZ, int FadeScreen)
{
	typedef bool (*f)(User*, int, int, int, int);
	typedef bool (*f2)(CUserSocket*);

	if(pUser->ValidUser() && !pUser->pSD->nInBattleField && pUser->pSD->nInPeaceZone && pUser->pSD->nKarma == 0)
	{
		if(pUser->pED->tvtUser.status == TvT::UserNone  && !pUser->pED->inEventPvp)
		{
			if(g_SpawnProtection.IsEnabled())
			{
				pUser->pED->spawnProtection = 1;	//start request
			}
		}
	}

	if(pUser->ValidUser())
	{
		pUser->ChangeTarget(NULL, true);
	}

	pUser->pCreatureController->AsyncDoNothing();
	
	if(pUser->IsNowTrade())
	{
		pUser->TradeCancel();
	}

	if(pUser->pSD->nIsPledgeLeader && pUser->HasAbnormal(179))
	{
		pUser->DispelByAbnormal(179, true);
	}

	if(pUser->ValidUser())
	{
		pUser->pSD->pExData->teleportTick = GetTickCount();
	}

	if(f(0x8151E0)(pUser, nX, nY, nZ, FadeScreen))
	{	

		if(pUser->ValidUser())
		{
			CNPC *pAganthion = pUser->pSD->pExData->Aganthion;
			if(pAganthion->ValidCreature())
			{
				if(pAganthion->pSD->nNpcClassID >= 1033910 && pAganthion->pSD->nNpcClassID <= 1033928)
				{
					pAganthion->TeleportToLocation(nX-30,nY-30,nZ,0);
				}
			}
		}

		g_CursedWeaponSystem.OnTeleport(pUser);
		return true;
	}

	if(pUser->pSD->activateOfflineShopTime || pUser->GetSocket()->pED->is_osr || pUser->GetSocket()->pED->is_osr_buff)
		f2(0x861690L)(pUser->pSocket);

	return false;
}

void PlayerAction::OnTimerExpired(User *pUser, int nTimerID)
{
	guard;

	if(nTimerID == 1986)
	{
		if(pUser->ValidUser())
		{
			//Scheme Buffer
			pUser->DispatchQueuedBuff();
		}
		unguard;
		return;
	}

	if(nTimerID == VALIDATE_AUTO_HP_TIMER)
	{
		g_ItemAutoConsume.OnTiggerHp(pUser);
		unguard;
		return;
	}else if(nTimerID == VALIDATE_AUTO_CP_TIMER)
	{
		g_ItemAutoConsume.OnTiggerCp(pUser);
		unguard;
		return;
	}else if(nTimerID == VALIDATE_AUTO_CP_ADV_TIMER)
	{
		g_ItemAutoConsume.OnTiggerCpAdv(pUser);
		unguard;
		return;
	}else if(nTimerID == VALIDATE_AUTO_MP_TIMER)
	{
		g_ItemAutoConsume.OnTiggerMp(pUser);
		unguard;
		return;
	}

	if(nTimerID == 0)
	{
		if(pUser->ValidUser())
		{
			pUser->pSD->nTimerTick++;

			UINT currentTime = static_cast<UINT>(time(0));

			if(g_SaveAbnormalsIntervalTime > 0)
			{
				if(pUser->pSD->nAlive)
				{
					if(pUser->pED->leftWorld == FALSE)
					{
						if((pUser->pSD->nTimerTick % g_SaveAbnormalsIntervalTime) == 0)
						{
							pUser->SaveInfectedSkills();
						}
					}
				}
			}

			if(pUser->pED->visualArmorUser.floodTimestamp_test < time(0) && pUser->pED->visualArmorUser.floodTimestamp_test>0)
			{
				VisualArmorUser& vUser = pUser->pED->visualArmorUser;
				vUser.armorId = 0;
				pUser->pED->visualArmorUser.floodTimestamp_test= 0;
				g_DB.RequestLoadVisualArmor(pUser->nDBID);
				if (pUser->GetSocket()->pED->IsLoadOfflineShop == 0)
				{
					PlayerAction::OnTeleportToLocation(pUser, static_cast<int>(pUser->pSD->Pos.x), static_cast<int>(pUser->pSD->Pos.y), static_cast<int>(pUser->pSD->Pos.z), 0);
				}
			}

			if(pUser->pED->hats_test_timestamp < time(0) && pUser->pED->hats_test_timestamp>0 && pUser->pED->hats_test_id > 0 )
			{
				pUser->pED->hats_test_timestamp = 0;
				pUser->pED->hats_test_id = 0;
				PlayerAction::OnTeleportToLocation(pUser, static_cast<int>(pUser->pSD->Pos.x), static_cast<int>(pUser->pSD->Pos.y), static_cast<int>(pUser->pSD->Pos.z), 0);
			}

			pUser->TimerExpiredForHiddenAbnormals();

			g_OfflineShopRestore.TimerExpired(pUser);


			if (g_achiv)
				g_Achivments.TimerExpired(pUser);


			/*if( (pUser->pED->uos_activateauto > 0) && (pUser->pED->uos_activateauto < currentTime))
			{
				pUser->pED->uos_activateauto = 0;
				g_OfflineSocketDB.Add(pUser->pSocket, pUser->pSocket->s);

				pUser->pSocket->socketStatus = 2;
				pUser->pSocket->s = -1;
				pUser->pSD->activateOfflineShopTime = _time32(0);
				
				g_SocketDB.SetStatus(pUser->pSocket, CSocketData::OFFLINE_SHOPPING);
				g_OfflineShopRestore.OnBeginOfflineShop(pUser->pSocket);
			}*/

			g_ItemAutoConsume.OnTiggerHp(pUser);
			g_ItemAutoConsume.OnTiggerCp(pUser);
			g_ItemAutoConsume.OnTiggerCpAdv(pUser);
			g_ItemAutoConsume.OnTiggerMp(pUser);

			g_TerritoryChecker.ValidateRideTerritory(pUser);

			//validate combat mode
			if(pUser->inCombatMode)
			{
				if(pUser->pED->broadcastCombatModeTimestamp < pUser->combatModeTimeStamp)
				{
					PlayerAction::OnBroadcastCombatModeStart(pUser);
				}
			}

			if(g_Captcha.IsEnabled())
			{
				if(pUser->pED->captchaProtectionTimeout)
				{
					if( pUser->pED->captchaProtectionTimeout  <= currentTime )
					{
						g_Captcha.DoPunishment(pUser,true);
						g_DB.RequestSaveCaptchaStatus(pUser->nDBID, pUser->pED->mobsKilled, pUser->pED->captchaWrongTimes, pUser->pED->captchaPeriod, 0, 0, pUser->pED->captchaJail);
					}else
					{
						INT32 diffTime = pUser->pED->captchaProtectionTimeout - currentTime;
						if((diffTime % 5) == 0 || diffTime < 5)
						{
							if(pUser->pED->captchaProtectionTimeSent != currentTime)
							{
								pUser->pED->captchaProtectionTimeSent = currentTime;
								//2634	1	Captcha System: You have $s1 second(s) to solve this question.	0	79	9B	B0	FF			0	0	0	0	0		none
								CSystemMessage msg(2634);
								msg.AddNumber(diffTime);
								pUser->SendSystemMessage(&msg);
							}
						}
					}
				}
			}				

			if(g_IndivVote.IsEnabled())
			{
				g_IndivVote.CheckVoteUser(pUser);
			}

			//RB FLAG SYSTEM
			/*if(g_FlagSystem.Enabled())
			{
				g_FlagSystem.PlayerFlag(pUser);
			}*/

			if(g_Jail.IsEnabled())
			{
				if( (pUser->pED->jailtimeout > 0) && (pUser->pED->jailtimeout < currentTime) )
				{
					g_Jail.RemovePlayerJail(pUser, false); //Maybe True in future?
				}

				if( (pUser->pED->jailtimeout > 0) && (pUser->pED->jailtimeout > currentTime) )
				{
					TerritoryData& td = pUser->pSD->pExData->territoryData;
					if(td.territoryId[JAIL_ZONE] == 0)
					{
						PlayerAction::OnTeleportToLocation(pUser, g_Jail.JailPosX(), g_Jail.JailPosY(), g_Jail.JailPosZ(), false);
					}
				}
			}

			if(g_SpawnProtection.IsEnabled())
			{
				if(pUser->pED->spawnProtectionTimeout)
				{
					if(pUser->pED->spawnProtectionTimeout <= currentTime)
					{
						g_SpawnProtection.DeactivateProtection(pUser);
					}else
					{
						INT32 diffTime = pUser->pED->spawnProtectionTimeout - currentTime;
						if((diffTime % 5) == 0 || diffTime < 5)
						{
							if(pUser->pED->spawnProtectionTimeSent != currentTime)
							{
								pUser->pED->spawnProtectionTimeSent = currentTime;
								//2514	1	a,The effect of Spawn Protection will expire in $s1 second(s).\0	0	79	9B	B0	FF	a,	a,	0	0	0	0	0	a,	a,none\0
								CSystemMessage msg(2514);
								msg.AddNumber(diffTime);
								pUser->SendSystemMessage(&msg);
							}
						}
					}
				}
			}

			//DEBUG
			/*CSummon *pSummon = pUser->GetSummonOrPet();
			if(pSummon->IsSummon())
			{
				g_Log.Add(CLog::Error, "[%s] NPC ID[%d]", __FUNCTION__, pSummon->pSD->nNpcClassID);
			}*/

			pUser->pSD->pExData->requestJoinParyRoom.Expired();
			g_OfflineShop.TimerExpired(pUser);
			if(g_PrivateStoreSystem.StoreInDB())
			{
				g_PrivateStoreSystem.TimerExpired(pUser);
			}
			if(g_VIPSystem.IsEnabled())
			{
				g_VIPSystem.TimerExpired(pUser);
			}

			if( g_AIOSystem.IsEnabled() )
			{
				g_AIOSystem.TimerExpired(pUser);
			}

			g_DailyPvP.TimerExpired(pUser);

			if((pUser->pSD->nStoreMode == 3 || pUser->pSD->nStoreMode == 5 || pUser->pSD->nStoreMode == 1) && (pUser->pSD->nTimerTick % 5) == 0)
			{
				if(!g_PrivateStoreSystem.GotEnoughAdenaToBuy(pUser))
				{
					pUser->QuitPrivateStore();
					if(pUser->pSocket)
					{
						pUser->pSocket->SendSystemMessage(L"You've got not enough adena to handle your private store!");
					}
				}
			}

			if((pUser->pSD->nTimerTick % 10) == 0 )
			{
				CBuilderCommand::ValidateBuilder(pUser);
			}

			if(CParty *pParty = pUser->GetParty())
			{
				if(pParty->GetMaster() == pUser)
				{
					INT32 partyCount = pUser->GetMPCCPartyAmount();
					if(partyCount > 0)
					{
						pUser->pSD->nIsCCOwner = 1;
						pUser->pSD->nCCPartyAmount = partyCount;
						if((pUser->pSD->nTimerTick % 5) == 0)
						{
							pUser->pSD->nCCMembersDistance = pUser->GetMPCCMemberDistance();
						}
					}
				}

				if(pUser->pSD->nCursedOwner)
				{
					pParty->LeaveParty(pUser);
					pUser->SendSystemMessage(L"You cannot be a party member while equipping cursed weapon!");
				}
			}else if(pUser->pSD->nIsCCOwner)
			{
				pUser->pSD->nIsCCOwner = 0;
				pUser->pSD->nCCPartyAmount = 0;
			}

			//Check if Faction Users are in same Faction ID UNDER BETA
			if(CParty *pParty = pUser->GetParty())
			{
				if(User *pPartyLeader = pParty->GetMaster())
				{
					if( pPartyLeader != pUser )
					{
						TerritoryData& td = pUser->pSD->pExData->territoryData;
						TerritoryData& td2 = pPartyLeader->pSD->pExData->territoryData;
					
						if((td.territoryId[FACTION_ZONE] != 0) && (td2.territoryId[FACTION_ZONE] != 0))
						{
							if( pPartyLeader->pED->nFactionID != pUser->pED->nFactionID )
							{
								pParty->LeaveParty(pUser);
								pUser->SendSystemMessage(L"You cannot be a party member while leader belongs to other Faction!");
							}
						}
					}
				}
			}

			if(!pUser->IsNowTrade())
			{
				if((pUser->pSD->nTimerTick % 10) == 0 )	//every 10 sec
				{
					DWORD color = 0;
					for(map<INT32, DWORD>::iterator it = g_ItemNicknameColor.begin(); it != g_ItemNicknameColor.end(); it++)
					{
						if(pUser->inventory.HaveItemByClassID(it->first, 1))
						{
							color = it->second;
						}
					}
					if(color != pUser->pED->nicknameColor)
					{
						pUser->pED->nicknameColor = color;
						pUser->SetUserInfoChanged();
						pUser->SetCharInfoChanged();
					}

					color = 0;
					for(map<INT32, DWORD>::iterator it = g_ItemTitleColor.begin(); it != g_ItemTitleColor.end(); it++)
					{
						if(pUser->inventory.HaveItemByClassID(it->first, 1))
						{
							color = it->second;
						}
					}
					if(color != pUser->pED->titleColor)
					{
						pUser->pED->titleColor = color;
						pUser->SetUserInfoChanged();
						pUser->SetCharInfoChanged();
					}
				}

				if((pUser->pSD->nTimerTick % 5) == 0)
				{
					pUser->ValidateItemExSkill();
				}

				if(g_ValidateStackableItems && (pUser->pSD->nTimerTick % 3) == 0)
				{
					if(!pUser->ValidateStackableItems())
					{
						pUser->pSD->pExData->kickTick = 2;
					}
				}
				if((pUser->pSD->nTimerTick % 30) == 0)
				{
					g_HeroSystem.TimerExpired(pUser);
				}
				if((pUser->pSD->nTimerTick % 25) == 0)
				{
					pUser->ValidateLifeTimeItems();
				}
			}
		}
	}

	typedef void(*f)(User*, int);
	f(0x00845090L)(pUser, nTimerID);	//User::TimerExpired

	if(pUser->ValidUser() && nTimerID == 0)
	{
		pUser->ValidateTerritory();
		g_TvT.TimerExpired(pUser);
		g_ItemDelivery.OnTimerExpired(pUser);
		/*if(g_Auction.IsEnabled())
		{
			if(pUser->pED->auctionUser.paymentAskTimestamp < time(0))
			{
				pUser->pED->auctionUser.paymentAskTimestamp = time(0) + 60;
				g_DB.RequestAuctionPaymentAsk(pUser->nDBID);
			}
		}*/

		if(pUser->pED->voteRewardMsgRequest)
		{
			pUser->pED->voteRewardMsgRequest = FALSE;
			g_VoteReward.OnLoad(pUser);
			g_DB.RequestSaveVotePoints(pUser->pSocket->accountId, pUser->nDBID, pUser->pED->voteRewardPoints);
		}
		
		LONG sendUserInfo = InterlockedExchange(&pUser->pED->userInfoChanged, FALSE);
		if(sendUserInfo)
		{
			pUser->SendUserInfo();
		}
		if(InterlockedExchange(&pUser->pED->charInfoChanged, FALSE))
		{
			pUser->SendCharInfo();
		}
		if(InterlockedExchange(&pUser->pED->itemListChanged, FALSE))
		{
			pUser->SendItemList(false);
		}
		if(InterlockedExchange(&pUser->pED->abnormalStatusChanged, FALSE))
		{
			pUser->SendAbnormalStatusInfo();
		}
		if(InterlockedExchange(&pUser->pED->validateParametersRequest, FALSE))
		{
			pUser->ValidateParameters();
		}
		/*if(InterlockedExchange(&pUser->pED->saveitemsex, FALSE))
		{
			pUser->SaveItemsExDB();
		}*/

		if(pUser->pSD->pExData->kickTick > 0)
		{
			pUser->pSD->pExData->kickTick--;
			if(pUser->pSD->pExData->kickTick == 0)
			{
				pUser->Kick();
			}
		}
	}
	unguard;
}

bool PlayerAction::UnequipItem(User *pUser, int nSlotType)
{
	if(pUser->ValidUser())
	{
		int result = Hair2Slot::User::UnequipItem2(pUser, nSlotType);
		if(result != -1)
			return result;

		if(pUser->pSD->nCursedOwner && nSlotType == CItem::LRHand)
				return false;

		if( (nSlotType == CItem::LRHand) || (nSlotType == CItem::RHand) || (nSlotType == CItem::LHand) )
		{
			//pUser->pED->WeapontTypeHand = 0;
			pUser->pED->nicknameColor = 0;
			pUser->SetUserInfoChanged();
			pUser->SetCharInfoChanged();
		}

		return pUser->UnEquipItem(nSlotType);
	}
	return false;
}

CParty *PlayerAction::OnUpdateHP(User *pUser)
{
	if(g_DuelSystem.IsEnabled())
	{
		if(pUser->ValidUser() && pUser->pSD->DuelInfo.DuelID && pUser->pSD->DuelInfo.Fighting)
		{
			g_DuelSystem.UpdateDuelUserInfo(pUser);
		}
	}

//	if(pUser->ValidUser())
//	{
//		if(pUser->pED->inEventPvp)
//			g_PvPEvents.UpdatepPvPUserInfo(pUser);
//	}


	return pUser->GetParty();
}

bool PlayerAction::UseItem(User *pUser, CItem *pItem, int nForce)
{
	if(pItem->IsValidItem() && pUser->ValidUser())
	{
		if(pUser->IsNowTrade())
		{
			pUser->TradeCancel();
			return false;
		}
		if(pUser->pSD->nStoreMode > 0)
		{
			pUser->SendSystemMessage(L"You cannot use any item while operating a private store!");
			return false;
		}

		if(pUser->pSD->nCursedOwner)
		{
			int nSlotType = pItem->pSID->nSlotType;
			if(nSlotType == 256 || nSlotType == 128 || nSlotType == 16384) //BLock equip any weapon/shield with CursedWeapon
			{
				return false;
			}else 
			if(pItem->pSID->nItemID == 6408) //Formal Wear
				return false;

			//block all soulshots and spiritshots
			if(pItem->pII->defaultAction == 3 || pItem->pII->defaultAction == 4)
			{
				return false;
			}

		}

		pUser->pED->WeapontTypeHand = pItem->pSID->nSlotType;

		//Fix For Raid Bombs
		if( pItem->pSID->nItemID > 9949 && pItem->pSID->nItemID < 9977 )
		{
			if(pUser->pSD->nInPeaceZone)
			{
				pUser->pSocket->SendSystemMessage(L"You cannot summon a raidbomb inside a peace zone!");
				return false;
			}
		}

		if(pUser->olympiadUser.IsInside())
		{
			for(list<int>::iterator Iter = g_OlympiadForbiddenItemList.begin(); Iter!= g_OlympiadForbiddenItemList.end();Iter++)
			{
				if((*Iter) == pItem->pSID->nItemID)
				{
					pUser->pSocket->SendSystemMessage(1508);
					return false;
				}
			}

			if(g_OlympiadDB.IsForbiddenItem(pItem->pSID->nItemID))
			{
				pUser->pSocket->SendSystemMessage(1508);
				return false;
			}

			for(UINT m=0;m<g_OlympiadForbiddenItemGrade.size();m++)
			{
				if(g_OlympiadForbiddenItemGrade[m] == pItem->pII->nCrystalType)
				{
					pUser->pSocket->SendSystemMessage(1508);
					return false;
				}
			}

			if(g_OlympiadMaxAllowedWeaponEnchant > 0 && pItem->pSID->nItemType == 0)
			{
				if(g_OlympiadMaxAllowedWeaponEnchant < pItem->pSID->nEnchantLevel)
				{
					pUser->pSocket->SendSystemMessage(1508);
					return false;
				}
			}
			if(g_OlympiadMaxAllowedArmorEnchant > 0 && (pItem->pSID->nItemType == 1 || pItem->pSID->nItemType == 2))
			{
				if(g_OlympiadMaxAllowedArmorEnchant < (int)pItem->pSID->nEnchantLevel)
				{
					pUser->pSocket->SendSystemMessage(1508);
					return false;
				}
			}

		}

		if(pUser->pED->tvtUser.status == TvT::UserFighting || pUser->pED->tvtUser.status == TvT::UserPreparing)
		{
			if(!g_TvT.CanUse(pItem))
			{
				pUser->pSocket->SendSystemMessage(L"You cannot use this item during TvT event.");
				return false;
			}
		}

		if(pUser->pED->tvtUser.status == TvT::UserFighting)
		{
			if(g_TvT.CtfUseWeapon(pUser,pItem))
			{
				pUser->pSocket->SendSystemMessage(L"No puede cambiar de item mientras llevas la bandera.");
				return false;
			}
		}

		int TerritoryID = pUser->pSD->nInBlockItemsZone;
		if(TerritoryID)
		{
			CBlockItemsTerritory *pTerritory = g_TerritoryChecker.GetTerritory(TerritoryID)->SafeCastBlockItems();
			if(pTerritory)
			{
				if(pTerritory->IsBlocked(pItem->pSID->nItemID))
				{
					pUser->GetSocket()->SendSystemMessage(61);
					return false;
				}
			}
		}

		if(TerritoryID)
		{
			CEventPvPTerritory *pTerritory = g_TerritoryChecker.GetTerritory(TerritoryID)->SafeCastEventPvP();
			if(pTerritory)
			{
				if(pTerritory->IsBlocked(pItem->pII->nCrystalType) && pTerritory->ItemsEscluidos(pItem->pSID->nItemID))
				{
					pUser->GetSocket()->SendSystemMessage(61);
					return false;
				}
				else if(pTerritory->CanUseEnchant(pItem->pSID->nEnchantLevel))
				{
					pUser->GetSocket()->SendSystemMessage(61);
					return false;
				}
			}
		}

		return pUser->UseItem(pItem, nForce);
	}
	return false;
}

bool PlayerAction::DeleteShipTicket(User *pUser, INT32 ticketId, INT32 count)
{
	if(pUser->ValidUser())
	{
		if(pUser->IsNowTrade())
			pUser->TradeCancel();

		if(CSummon *pSummon = pUser->GetSummon())
		{
			pUser->DespawnSummon();
		}
	}

	typedef bool (*f)(User*, INT32, INT32);
	UINT64 addr = (*reinterpret_cast<PUINT64>(pUser));
	addr += 0x578;
	addr = (*reinterpret_cast<PUINT64>(addr));

	return f(reinterpret_cast<f>(addr))(pUser, ticketId, count);
}

bool PlayerAction::OnHear(User* pUser, User* pTalker, PWCHAR wTalkerName, const WCHAR* wMessage, int nType)
{
	typedef bool (*f)(User*, User*, PWCHAR, const WCHAR*, int);
	if(pUser->ValidUser())
	{
		if(nType == 9) //alliance
		{
			if(pUser->IsAcademyMember())
				return false;
		}
	}
	return f(0x82D810L)(pUser, pTalker, wTalkerName, wMessage, nType);
}

bool PlayerAction::OnClassChange(User *pUser, int nClass)
{
	bool bRet = pUser->ChangeClass(nClass);
	if(pUser->ValidUser())
	{
		ClanSys::OnChangeClass(pUser, nClass);
	}
	if(bRet)
	{
		pUser->requestSaveCharacterInfoTick = 195;
	}
	return bRet;
}

void PlayerAction::OnSendXPnSP(CUserSocket *pSocket, const char* format, BYTE opCode, DWORD MsgID, DWORD NumOfVars, DWORD Type1, int Exp, DWORD Type2, int SP)
{
	if(User *pUser = pSocket->GetUser())
	{

		UINT currentThreadIdx = GetThreadIndex();
		if(currentThreadIdx < 32)
		{
			if(g_IsDistributingExpSp[currentThreadIdx])
			{
				if(pUser->CanGetPartyBonus(g_DistributingCreature[currentThreadIdx]))
				{
					double modExp = static_cast<double>(Exp);
					modExp *= g_PartyExpRate;
					Exp = static_cast<INT32>(modExp);

					modExp = static_cast<double>(SP);
					modExp *= g_PartyExpRate;
					SP = static_cast<INT32>(modExp);
				}
			}
		}

		if(currentThreadIdx < 26 )
		{
			CNPC *pNpc = g_KilledNpc[currentThreadIdx];
			if(g_ChampionNpc.IsEnabled())
			{
				int nTeam = pNpc->pSD->teamType;
				int nClassID = pNpc->pSD->nNpcClassID;
				if(nTeam)
				{
					if(g_ChampionNpc.IsChampionNPC(nClassID))
					{
						Exp = g_ChampionNpc.GetExp(Exp, nClassID, nTeam);
						SP = g_ChampionNpc.GetExp(SP, nClassID, nTeam);
					}
				}
			}
		}

		if(pUser->pSD->vipLevel)
		{
			Exp = g_VIPSystem.GetExp(Exp, pUser->pSD->vipLevel);
			SP = g_VIPSystem.GetSP(SP, pUser->pSD->vipLevel);
		}

		/* Happy Hours */
		Exp = g_HappyHours.GetExp(Exp);
		SP = g_HappyHours.GetSP(SP);

		if(pUser->pSD->pExData->SkillMod.stopExp || pUser->pSD->pExData->stopIncExp)
		{
			return;
		}

		//exp curve
		{
			double exp = static_cast<double>(Exp);
			exp *= g_ExpCurve[pUser->pSD->nLevel];
			Exp = static_cast<INT32>(exp);
		}
		
		double exp = static_cast<double>(Exp);
		exp *= pUser->pSD->pExData->SkillMod.bonusExp;
		exp *= g_DnNSystem.GetRate(DnN::RateExp);
		Exp = static_cast<INT32>(exp);

		double sp = static_cast<double>(SP);
		sp *= pUser->pSD->pExData->SkillMod.bonusSp;
		sp *= g_DnNSystem.GetRate(DnN::RateSp);
		SP = static_cast<INT32>(sp);

		//exp overflow
		INT64 n4Percent = pUser->pSD->nExp;
		n4Percent *= 5;
		n4Percent /= 100;
		n4Percent *= -1;

		if(Exp < n4Percent)
		{
			n4Percent *= -1;
			Exp = n4Percent;
		}

		//sp overflow
		if(SP == -2147483648)
		{
			INT64 sp = pUser->pSD->nSp;
			sp *= 5;
			sp /= 100;
			SP = sp;
		}
	}

	pSocket->Send(format, opCode, MsgID, NumOfVars, Type1, Exp, Type2, SP);
}

bool PlayerAction::OnDeleteItemInInventoryBeforeCommit(User *pUser, int itemId, int amount)
{
	if(pUser->ValidUser())
	{
		if(pUser->IsNowTrade())
		{
			pUser->TradeCancel();
		}
	}

	for(UINT n=0;n<g_InfinityArrow.size();n++)
	{
		if(itemId == g_InfinityArrow[n])
		{
			return true;
		}
	}

	typedef bool(*f)(User*, int, int);
	return f(0x827150L)(pUser, itemId, amount);
}

void PlayerAction::OnSendETCBuffStatusInfo(CSocket *pSocket, const char *format, ...)
{
	va_list tag;
	va_start(tag, format);
/* c */ BYTE cHeader = va_arg(tag, BYTE); 
/* d */ DWORD dCharges = va_arg(tag, DWORD); 
/* d */ DWORD dWeightPenalty = va_arg(tag, DWORD); 
/* d */ DWORD dBlockChats = va_arg(tag, DWORD); 
/* d */ DWORD dDangerArea = va_arg(tag, DWORD); 
/* d */ DWORD dGradePenalty = va_arg(tag, DWORD); 
	va_end(tag);
	//New C5 Things
	int nCharmOfCourage = 0;
	User *pUser = pSocket->CastUserSocket()->GetUser();
	int nDeathPenalty = 0;
	if(pUser->ValidUser())
	{
		nDeathPenalty = pUser->pSD->nDeathPenalty;
		if(dGradePenalty == 0 && pUser->pSD->pExData->ArmorPenalty)
			dGradePenalty = 1;
		if(pUser->pED->blockChatZoneId)
			dBlockChats = 1;

		if(g_GradePenalty.Enabled())
		{
			g_GradePenalty.CheckState(pUser, dGradePenalty > 0 ? true : false);
		}

		if(g_Captcha.EtcBuffStatusReplace())
			nCharmOfCourage = pUser->pED->captchaPeriod;
		else
		nCharmOfCourage = pUser->pED->charmOfCourageLevel;
		
	}

	pSocket->Send("cddddddd", cHeader, dCharges, dWeightPenalty, dBlockChats, dDangerArea, dGradePenalty, nCharmOfCourage, nDeathPenalty);
}

void PlayerAction::SaveCharacterInfo(INT64 nCDB, const char *format, ...)
{
	CPacket pck;
	va_list list;
	va_start(list, format);
/*c*/	BYTE opCode = va_arg(list, BYTE); pck.WriteC(opCode);
/*d*/	DWORD nCharID = va_arg(list, DWORD); pck.WriteD(nCharID);
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*f*/	pck.WriteF(va_arg(list, double));
/*f*/	pck.WriteF(va_arg(list, double));
/*f*/	pck.WriteF(va_arg(list, double));
/*f*/	pck.WriteF(va_arg(list, double));
/*f*/	pck.WriteF(va_arg(list, double));
/*f*/	pck.WriteF(va_arg(list, double));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
/*d*/	pck.WriteD(va_arg(list, DWORD));
	va_end(list);
	User *pUser = g_UserDB.GetUserByDBID(nCharID);
	if(pUser->ValidUser())
	{
		pck.WriteD(pUser->GetAugmentationID());
		if(g_Config.IsSet(CConfig::SPIRIT_SYSTEM))
		{
			pck.WriteD(pUser->pSD->nSpiritCounter);
		}
		else
		{
			pck.WriteD(0);
		}

		int hair0 = 0, hair2 = 0, hairall = 0;
		Hair2Slot::GetDataBaseEquipID(pUser, hair0, hair2, hairall);

		pck.WriteD(hair2); //hairdeco
		pck.WriteD(hairall); //hairall



		pck.WriteD(0); //EffectiveMana0
		pck.WriteD(0); //EffectiveMana1
		pck.WriteD(0); //EffectiveMana2
		pck.WriteD(0); //EffectiveMana3

	}else
	{
		pck.WriteD(NULL); //augmentation
		pck.WriteD(NULL); //spirit_count
		pck.WriteD(NULL); //hairdeco
		pck.WriteD(NULL); //hairall
		pck.WriteD(NULL); //EffectiveMana0
		pck.WriteD(NULL); //EffectiveMana1
		pck.WriteD(NULL); //EffectiveMana2
		pck.WriteD(NULL); //EffectiveMana3
	}

	 //ddddddddffffffddddddddddddddddddddddddddddddddd CachedPacket
	//cddddddddffffffddddddddddddddddddddddddddddddddd L2Server
	typedef void (*f)(INT64, const char *, size_t, PCHAR);

	if(pUser->ValidUser())
	{
		if(!pUser->pSD->activateOfflineShopTime)
			f(0x0052ABE0L)(nCDB, "b", pck.GetSize(), pck.GetBuff());
	}
	else
		f(0x0052ABE0L)(nCDB, "b", pck.GetSize(), pck.GetBuff()); //only this had here
}

extern BOOL g_OlympiadCheckHWID;
extern BOOL g_OlympiadEnterLast10Minute;
extern BOOL g_OlympiadThirdClassSummons;

bool PlayerAction::RegisterInOlympiad(COlympiadUser *pOU)
{
	User *pUser = (User*)((UINT64)pOU - (UINT64)0x2CB0);
	if(pUser->ValidUser() && !pUser->pSD->nCursedOwner && pUser->pSD->activateOfflineShopTime == 0)
	{
		if( pUser->olympiadUser.GetState() != 0 )
		{
			pUser->GetSocket()->SendSystemMessage(1502);
			return false;
		}

		if(g_OlympiadCheckHWID)
		{
			if(g_UserDB.GetOlympiadUserAmountByIPnHWID(pUser->pSocket->addr.S_un.S_addr, pUser->pSocket->pED->longHWID.hash) > 0)
			{
				//send sys message
				pUser->SendSystemMessage(L"You already are registered in olympiad with other character!");
				return false;
			}
		}

		if (pUser->pED->tvtUser.status != TvT::UserNone)
		{
			pUser->SendSystemMessage(L"No puedes anotarte porque estas anotado en otro evento!");
			return false;
		}

		if(pUser->pED->aioId > 0)
		{
			pUser->SendSystemMessage(L"The AIO characters cannot participe in Olympiad Games!");
			return false;
		}
		tm ti;
		GetTimeInfo(ti);
		int endHour = 24;
		//check for 10 minutes before the end
		if(SSQPart::none == SSQSystem::GetInstance()->GetWinner())
		{
			//event period or none
			endHour = g_OlympiadPeriod[ti.tm_wday][0].endHour;
		}else
		{
			endHour = g_OlympiadPeriod[ti.tm_wday][1].endHour;
		}

		if(endHour == 0)
			endHour = 24;

		if(!g_OlympiadEnterLast10Minute)
		{
			if( ( ti.tm_hour + 1 ) == endHour )
			{
				if(ti.tm_min > 50)
				{
					pUser->SendSystemMessage(L"There's only 10 minutes left till olympiad fights ends, it's too late to register.");
					return false;
				}
			}
		}

		return pOU->RegisterOlympiadEntry();
	}
	return false;
}

int PlayerAction::OnDieLooseExp(User *pUser, int nLostExp)
{
	if(pUser->ValidUser() && nLostExp)
	{
		//g_Log.Add(CLog::Blue, "[%s] LostExp[%d] - 1", __FUNCTION__, nLostExp);

		//Fix For Faction Zone
		TerritoryData& td = pUser->pSD->pExData->territoryData;
		if(td.territoryId[FACTION_ZONE] != 0)
		{
			pUser->SetExpDown(-1);
			return pUser->ExpDown(-1);
		}

		if(pUser->pSD->nCursedVictim)
		{
			pUser->pSD->nCursedVictim = 0;
			//g_Log.Add(CLog::Blue, "[Ext] User[%S] killed by cursed weapon owner.", pUser->pSD->wszName);
			pUser->SetExpDown(-1);
			return pUser->ExpDown(-1);
		}

		if(pUser->pED->charmOfCourageLevel > 0 && (pUser->pSD->nInBattleField || pUser->inPvpZone))
		{
			pUser->SetExpDown(-1);
			return pUser->ExpDown(-1);
		}

		if(pUser->pED->tvtUser.status == TvT::UserFighting)
		{
			pUser->SetExpDown(-1);
			return pUser->ExpDown(-1);
		}

		if(pUser->pED->inEventPvp > 0)
		{
			pUser->SetExpDown(-1);
			return pUser->ExpDown(-1);
		}

		if(pUser->pSD->nLevel < 9 && pUser->pSD->nKarma == 0)
		{
			if(pUser->pSD->nExp > 1)
			{
				pUser->SetExpDown(-1);
				return pUser->ExpDown(-1);
			}else
			{
				pUser->SetExpDown(0);
				return pUser->ExpDown(0);
			}
		}
		if(pUser->pSD->nLevel == 76)
		{
			nLostExp /= 2;
			pUser->SetExpDown(nLostExp);
		}else if(pUser->pSD->nLevel == 77)
		{
			nLostExp/=2;
			pUser->SetExpDown(nLostExp);
		}else if(pUser->pSD->nLevel == 78)
		{
			nLostExp/=3;
			pUser->SetExpDown(nLostExp);
		}else if(pUser->pSD->nLevel == 79)
		{
			nLostExp/=3;
			pUser->SetExpDown(nLostExp);
		}else if(pUser->pSD->nLevel == 80)
		{
			nLostExp/=4;
			pUser->SetExpDown(nLostExp);
		}
		
		
		if(pUser->pSD->pExData && pUser->pSD->pExData->SkillMod.nDecreaseLostExp)
		{
			double dPercent = 100 - pUser->pSD->pExData->SkillMod.nDecreaseLostExp;
			dPercent /= 100;
			dPercent *= nLostExp;
			nLostExp = (int)dPercent;
			pUser->SetExpDown(nLostExp);
			//g_Log.Add(CLog::Blue, "[%s] Called", __FUNCTION__);
		}
	}
	//g_Log.Add(CLog::Blue, "[%s] LostExp[%d] - 2", __FUNCTION__, nLostExp);
	return pUser->ExpDown(nLostExp);
}

void PlayerAction::OnDieDropItem(User *pUser, bool bOnBattlefield)
{
	typedef void (*f)(User*, bool);
	if(g_DeathPenalty.IsEnabled())
	{
		if(pUser->ValidUser() && pUser->pSD->nKarma > 0 && pUser->pSD->nPkCount >= 5)
		{
			f(0x81C310)(pUser, bOnBattlefield);
		}
	}else
	{
		if(pUser->ValidUser())
		{
			if(pUser->pED->tvtUser.status != TvT::UserFighting)
			{
				if(pUser->pSD->nKarma > 0 && pUser->pSD->nPkCount >= 5)
				{
					f(0x81C310)(pUser, bOnBattlefield);
				}
				else
				{
					if(!g_NoDropPlayerOnDie)
						f(0x81C310)(pUser, bOnBattlefield);			//User::OnDieDropItem
				}
			}
		}
	}
}

bool PlayerAction::OnOlympiadStartMatch(COlympiadField *pField)
{
	bool bRet = pField->CheckGameExit();
	if(!bRet)
	{
		CObjectSP ObjectSP;
		CObjectSP::GetUserByDBID(&ObjectSP, pField->nPlayer1DBID);
		User *pUser = ObjectSP.pObject->GetUser();
		if(pUser->ValidUser())
		{
			if(!pUser->pSD->nAlive)
			{
				g_Log.Add(CLog::Error, "[%s] Death user[%S] participed to olympiad.", __FUNCTION__, pUser->pSD->wszName);
				pUser->Revive();
			}
			if(pUser->pED->spawnProtection)
			{
				g_SpawnProtection.DeactivateProtection(pUser);
			}
			
			if(g_OlympiadRestoreStatsOnFightStart)
			{
				pUser->pSD->fHP = pUser->pSD->MaxHP;
				pUser->pSD->fCP = pUser->pSD->MaxCP;
				pUser->pSD->fMP = pUser->pSD->MaxMP;
				pUser->SendHpInfo();
				pUser->SendMpInfo();
			}

			if(g_OlympiadStopActionOnFightStart)
			{
				pUser->pCreatureController->AsyncDoNothing();
			}
		}
		CObjectSP ObjectSP2;
		CObjectSP::GetUserByDBID(&ObjectSP2, pField->nPlayer2DBID);
		pUser = ObjectSP2.pObject->GetUser();
		if(pUser->ValidUser())
		{
			if(!pUser->pSD->nAlive)
			{
				g_Log.Add(CLog::Error, "[%s] Death user[%S] participed to olympiad.", __FUNCTION__, pUser->pSD->wszName);
				pUser->Revive();
			}
			if(pUser->pED->spawnProtection)
			{
				g_SpawnProtection.DeactivateProtection(pUser);
			}
			/*pUser->pSD->fHP = pUser->pSD->MaxHP;
			pUser->pSD->fCP = pUser->pSD->MaxCP;
			pUser->pSD->fMP = pUser->pSD->MaxMP;
			pUser->SendHpInfo();
			pUser->SendMpInfo();*/

			if(g_OlympiadRestoreStatsOnFightStart)
			{
				pUser->pSD->fHP = pUser->pSD->MaxHP;
				pUser->pSD->fCP = pUser->pSD->MaxCP;
				pUser->pSD->fMP = pUser->pSD->MaxMP;
				pUser->SendHpInfo();
				pUser->SendMpInfo();
			}

			if(g_OlympiadStopActionOnFightStart)
			{
				pUser->pCreatureController->AsyncDoNothing();
			}
		}

		User *pU1 = ObjectSP.pObject->SafeCastUser();
		User *pU2 = ObjectSP2.pObject->SafeCastUser();

		if(pU1 && pU2)
		{
			//Olympiad buff support
			vector<SkillPchId>& b1 = g_OlympiadDB.GetBuffSupport(pU1->pSD->nClass, pU2->pSD->nClass);
			vector<SkillPchId>& b2 = g_OlympiadDB.GetBuffSupport(pU2->pSD->nClass, pU1->pSD->nClass);
			for(UINT n=0;n<b1.size();n++)
			{
				if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(b1[n].skillId, b1[n].level))
				{
					pSI->ActivateSkill(pU1, pU1);
				}
			}
			for(UINT n=0;n<b2.size();n++)
			{
				if(CSkillInfo *pSI = g_SkillDB.GetSkillInfo(b2[n].skillId, b2[n].level))
				{
					pSI->ActivateSkill(pU2, pU2);
				}
			}
		}
	}
	return bRet;
}

void PlayerAction::OnOlympiadFinishMatch(COlympiadField *pOF)
{
	if(pOF)
	{
		CObjectSP ObjectSP1;
		CObjectSP::GetUserByDBID(&ObjectSP1, pOF->nPlayer1DBID);
		if(ObjectSP1.pObject->GetUser()->ValidUser())
		{
			User *pUser = ObjectSP1.pObject->GetUser();
			if(pUser->pSD->nAlive)
			{
				pUser->pCreatureController->AsyncDoNothing();
			}
		}
		CObjectSP ObjectSP2;
		CObjectSP::GetUserByDBID(&ObjectSP2, pOF->nPlayer2DBID);
		if(ObjectSP2.pObject->GetUser()->ValidUser())
		{
			User *pUser = ObjectSP2.pObject->GetUser();
			if(pUser->pSD->nAlive)
			{
				pUser->pCreatureController->AsyncDoNothing();
			}
		}
	}
	pOF->StatusFinishMatch();
}

void PlayerAction::OnOlympiadEscaping(User *pUser)
{
	if(pUser->ValidUser())
	{
		pUser->DispelAllByGM();
		pUser->ResetSkillReuse(); //Resetting skill reuse after match.
		//Adding Clan Skills
		CPledge *pPledge = pUser->GetPledge();
		if(pPledge)
		{
			pPledge->AcquirePledgeSkills(pUser);
		}

		pUser->pED->InstanceId = 0;
	}
}

bool PlayerAction::OnEnteringOlympiadStadion(COlympiadField *pOlympiadField)
{
	CObjectSP user1Sp;
	CObjectSP user2Sp;

	CObjectSP::GetUserByDBID(&user1Sp, pOlympiadField->nPlayer1DBID);
	CObjectSP::GetUserByDBID(&user2Sp, pOlympiadField->nPlayer2DBID);

	//Anty soe and some other exploit fix
	if(User *pUser = user1Sp.pObject->SafeCastUser())
	{
		pUser->pCreatureController->AsyncDoNothing();
		pUser->pSD->nWaitingForMatch = 0;
		if(g_SchemeBuffer.IsEnabled())
		{
			pUser->ClearQueuedBuffs();
		}
		pUser->TurnOffToggleSkills();
		if(g_InfinityShot.IsEnabled())
		{
			g_InfinityShot.AutoOff(pUser);
		}
		if(g_SpiritShotExtension)
		{
			g_InfinityShot.AutoOff_Normal(pUser);
		}
		if(pUser->pSD->nAlive == 0)
				pUser->Revive();
	}

	if(User *pUser = user2Sp.pObject->SafeCastUser())
	{
		pUser->pCreatureController->AsyncDoNothing();
		pUser->pSD->nWaitingForMatch = 0;
		if(g_SchemeBuffer.IsEnabled())
		{
			pUser->ClearQueuedBuffs();
		}
		pUser->TurnOffToggleSkills();
		if(g_InfinityShot.IsEnabled())
		{
			g_InfinityShot.AutoOff(pUser);
		}
		if(g_SpiritShotExtension)
		{
			g_InfinityShot.AutoOff_Normal(pUser);
		}
		if(pUser->pSD->nAlive == 0)
				pUser->Revive();
	}

	bool bReturn = pOlympiadField->SummonUser();
	if(bReturn)
	{
		if(User *pUser = user1Sp.pObject->SafeCastUser())
		{
			//deleting clan skills
			for(UINT n=370; n<392; n++)
			{
				pUser->DeleteSkill(n);
			}
			pUser->ValidateParameters();
			pUser->ClearHiddenAbnormals();
			pUser->pSD->pExData->HerbAbnormalMgr.Clear(-1);
			if(g_DuelSystem.IsEnabled())
			{
				if(pUser->pSD->DuelInfo.DuelID)
					g_DuelSystem.Interrupt(pUser->pSD->DuelInfo.DuelID);
			}
			
			COlympiadSystem::ValidateEquippedItems(pUser);
			pUser->DispelAllByGM();

			if (OlympiadInstanceEnable)
				pUser->pED->InstanceId = OlympiadInstanceCount;

			if(g_OlympiadThirdClassSummons)
			{
				CSummon *pSummon = pUser->GetSummonOrPet();
				if(pSummon->IsSummon())
				{
					if(pSummon->pSD->nNpcClassID == 1014836 ||
						pSummon->pSD->nNpcClassID == 1014837 ||
						pSummon->pSD->nNpcClassID == 1014838 )
					{
						pUser->DespawnSummon();
						pUser->SendSystemMessage(L"You cannot use this summon into Olympiad!");
					}
				}
			}
		}else
		{
			g_Log.Add(CLog::Blue, "[%s] Cannont find First User[%d].", __FUNCTION__, pOlympiadField->nPlayer1DBID);
		}

		if(User *pUser = user2Sp.pObject->SafeCastUser())
		{
			//deleting clan skills
			for(UINT n=370; n<392; n++)
			{
				pUser->DeleteSkill(n);
			}
			pUser->ValidateParameters();
			pUser->ClearHiddenAbnormals();
			pUser->pSD->pExData->HerbAbnormalMgr.Clear(-1);
			if(g_DuelSystem.IsEnabled())
			{
				if(pUser->pSD->DuelInfo.DuelID)
					g_DuelSystem.Interrupt(pUser->pSD->DuelInfo.DuelID);
			}
			
			COlympiadSystem::ValidateEquippedItems(pUser);
			pUser->DispelAllByGM();

			if (OlympiadInstanceEnable)
				pUser->pED->InstanceId = OlympiadInstanceCount;

			if(g_OlympiadThirdClassSummons)
			{
				CSummon *pSummon = pUser->GetSummonOrPet();
				if(pSummon->IsSummon())
				{
					if(pSummon->pSD->nNpcClassID == 1014836 ||
						pSummon->pSD->nNpcClassID == 1014837 ||
						pSummon->pSD->nNpcClassID == 1014838 )
					{
						pUser->DespawnSummon();
						pUser->SendSystemMessage(L"You cannot use this summon into Olympiad!");
					}
				}
			}
		}else
		{
			g_Log.Add(CLog::Blue, "[%s] Cannont find Second User[%d].", __FUNCTION__, pOlympiadField->nPlayer1DBID);
		}


			if (OlympiadInstanceEnable)
				OlympiadInstanceCount++;

	}
	return bReturn;
}

void PlayerAction::ObserverStart(User *pUser, int x, int y, int z, int yaw, int pitch, int period)
{
	typedef void (*f)(User*, int, int, int, int, int, int);
	
	if(pUser->ValidUser())
	{
		if(pUser->pSD->nStoreMode != 0)
		{
			pUser->SendSystemMessage(L"You cannot use observer mode when operating private store!");
			return;
		}
		if(pUser->olympiadUser.GetState() != 0)
		{
			pUser->SendSystemMessage(L"You cannot use observer mode when participing in Olympiad Fights!");
			return;
		}

		if(pUser->IsNowTrade())
			pUser->TradeCancel();

		pUser->pSD->nIsObserver = 1;
	}
	
	f(0x833880L)(pUser, x, y, z, yaw, pitch, period);
}

void PlayerAction::ObserverEnd(User *pUser)
{
	typedef void (*f)(User*);

	if(pUser->ValidUser())
	{
		if(pUser->IsNowTrade())
			pUser->TradeCancel();
		
		pUser->pSD->nIsObserver = 0;
	}

	f(0x813390L)(pUser);
}


void PlayerAction::OnPickUpItem(CInventory *pInventory, CItem *pItem, int nChangedType)
{
	//Normal Execution
	pInventory->SetInventoryChanged(pItem, nChangedType);
	User *pUser = pInventory->GetOwner()->GetUser();
	if(pUser->ValidUser())
	{
		g_CursedWeaponSystem.OnPickUp(pUser, pItem);
	}
}

void PlayerAction::OnAddItemToInventory(CInventory *pInventory, CItem *pItem, int nType)
{
	User *pUser = pInventory->GetOwner()->GetUser();
	if(nType == CInventory::ADD)
	{
		if(pItem->IsValidItem())
		{
			if(pUser->ValidUser())
			{
				g_Augmentation.MultiSellAddItem(pUser, pItem);
			}
		}
	}
	pInventory->SetInventoryChanged(pItem, nType);
	if(nType == CInventory::ADD)
	{

	}else if(nType == CInventory::UPDATE)
	{
		if(pItem->IsValidItem())
		{
			if(UINT lifeTime = g_ItemDBEx.GetLifeTime(pItem->pSID->nItemID))
			{
			//	g_Log.Add(CLog::Blue, "[%s] Update item stat [%d] item id [%d] count old life time[%d] new [%d]", __FUNCTION__, pItem->pSID->nItemID, pItem->pSID->nItemAmount, (pItem->nLifeTime - time(NULL)), (time(NULL) + LifeTime));
				pItem->nLifeTime = (time(0) + lifeTime);
				if(pUser->ValidUser())
				{
					//Send sys message
					//2411	1	$s1's life time has been refreshed.	0	79	9B	B0	FF			0	0	0	0	0		none
					CSystemMessage msg(2411);
					msg.AddItem(pItem->pSID->nItemID);
					pUser->SendSystemMessage(&msg);
				}		
			}
		}
	}
}

void PlayerAction::LoadItemsPacket(LPVOID pCDB, User *pUser)
{
	typedef void (*f)(LPVOID, User*);
	f(0x5314B0)(pCDB, pUser); //g_DB.RequestGetMacro(User *pUser)
}

void PlayerAction::OnLeaveWorld(User *pUser)
{
	if(pUser->ValidUser())
	{
		if(g_UserDB.GetUserByServerId(pUser->nObjectID))
		{
			try
			{

				if(pUser->pED->nInCustomEventClanZone)
				{
					CPledge *pPledge = pUser->GetPledge();
					if(pPledge && pPledge->pSD)
					{
						if(pUser->pSD->nAlive)
							g_TerritoryChecker.updateClanUserCount(pPledge->pSD->nDBID, -1);
					}
				}


				if(int territoryId = g_TerritoryChecker.IsInTerritory(pUser, HWID_LIMIT_ZONE))
				{
					if(CHwidLimitTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastHwidLimit())
					{
						map<UINT, User*>::iterator Iter =  g_TerritoryChecker.m_users.find(pUser->nObjectID);
						if(Iter!= g_TerritoryChecker.m_users.end())
						{
						 g_TerritoryChecker.m_users.erase(Iter);
						}
					}
				}

				if(g_DuelSystem.IsEnabled())
				{
					if(pUser->pSD->DuelInfo.DuelID)
						g_DuelSystem.LeaveWorld(pUser);
				}

				if(g_SchemeBuffer.IsEnabled())
				{
					g_DB.RequestSaveBuffList(pUser);
				}


				g_Championship.OnLeaveWorld(pUser);

				g_Achivments.Save(pUser);

				g_CursedWeaponSystem.OnLeaveWorld(pUser);
				ClanSys::LeaveWorld(pUser);
				COlympiadSystem::OlympiadFieldOnGameExit(pUser);
				if(g_PrivateStoreSystem.StoreInDB())
				{
					if(pUser->pSD->nStoreMode == 3 || pUser->pSD->nStoreMode == 5 || pUser->pSD->nStoreMode == 1)
					{
						g_PrivateStoreSystem.OnDeleteStore(pUser);
					}
				}
				if(pUser->pED->tvtUser.status != TvT::UserNone)
				{
					//g_TvT.OnExit(pUser);
				}

				g_PartyWaitingList.DelMember(pUser);
				
				if(g_SaveInstancesOnDB)
					pUser->SaveInstances();

				g_UserCache.OnLeaveWorld(pUser);
				g_SocketDB.SetStatus(pUser->GetSocket(), CSocketData::LEAVING_WORLD);
				
				if(pUser->pSD->nActiveUser == 0)
				{
					pUser->SaveInfectedSkills();
				}

				//Get Items and save them
				//pUser->SaveItemsExDB();

				g_DB.RequestSaveSubjob(pUser->nDBID, pUser->pSD->nSubClassIndex, pUser->pSD->fHP, pUser->pSD->fMP, pUser->pSD->nExp, pUser->pSD->nSp, pUser->pSD->nLevel, pUser->pSD->nHenna1, pUser->pSD->nHenna2, pUser->pSD->nHenna3);
				pUser->pED->leftWorld = TRUE;

			}catch(...)
			{
				EXCEPTION_LOG;
			}
		}
	}else
		g_Log.Add(CLog::Error, "[%s] Invalid User !!!", __FUNCTION__);

	//Normal Execution
	typedef void(*f)(User*);
	f(0x4D98F0L)(pUser);
}

void PlayerAction::IncreaseKarma(User *pUser, bool bWithPk)
{
	typedef void(*f)(User*, bool);

	if(pUser->pSD->nInCustomPvpZone)
	{
		return;
	}
	if(pUser->pED->nInFactionPvpZone)
	{
		return;
	}
	if(pUser->pSD->nCursedOwner)
	{
		bWithPk = false;
		return;
	}

	f(0x8146A0)(pUser, bWithPk);
}

int PlayerAction::OnGetRelationTo(User *pUser, User *pAttacker)
{
	typedef UINT (*_grt)(User*,User*);
	_grt grt = (_grt) 0x008008B0;
	//pUser - Target pCreature - Caster

	if(pUser->ValidUser() && pAttacker->ValidUser())
	{
		if(pUser->pSD->DuelInfo.DuelID && pUser->pSD->DuelInfo.DuelID == pAttacker->pSD->DuelInfo.DuelID && pUser->pSD->DuelInfo.Fighting)
			if(pAttacker->pSD->DuelInfo.DuelTeam > 0 && pAttacker->pSD->DuelInfo.DuelTeam!=pUser->pSD->DuelInfo.DuelTeam)
				return 0x6C4;

		if(pUser->pED->tvtUser.status == TvT::UserFighting && pAttacker->pED->tvtUser.status == TvT::UserFighting)
		{
			if(pUser->pED->tvtUser.team != pAttacker->pED->tvtUser.team)
			{
				return 0x6C4;
			}else
			{
				UINT Relation = grt(pUser, pAttacker);
				Relation |= User::IN_MY_PARTY;
				return Relation;
			}
		}

		//Custom EVENTO PVP Zone
		if(pUser->pED->inZoneCustomEventPvp || pAttacker->pED->inZoneCustomEventPvp)
		{
			return 0x6C4;
		}

		if(pUser->IsSameAbnormalTeam(pAttacker))
		{
			UINT Relation = grt(pUser, pAttacker);
			Relation |= User::IN_MY_PARTY;
			return Relation;
		}

		if(g_AttackWarWithoutCTRL)
		{
			if(!pUser->IsMyParty(pAttacker) && pUser->pSD->nInPeaceZone == 0 && pUser->pSD->nPledgeID > 0 && pAttacker->pSD->nPledgeID > 0 && pUser->pSD->nPledgeID != pAttacker->pSD->nPledgeID)
			{
				if(CPledge *pPledge = pUser->GetPledge())
				{
					if(!pUser->IsAcademyMember() && pUser->olympiadUser.IsInside() == FALSE)
					{
						if(pUser->pSD->bGuilty == false)
						{
							if(pPledge->IsInWarWithEx(pAttacker->pledgeServerId))
							{
								UINT relation = grt(pUser, pAttacker);
								relation |= User::PVP_FLAG;
								return relation;
							}
						}
					}
				}
			}
		}

		//Custom PvP Zone
		if(pUser->pSD->nInCustomPvpZone || pAttacker->pSD->nInCustomPvpZone)
		{
			if(!pUser->IsInAlliance(pAttacker) && !pUser->IsMyParty(pAttacker))
				return 0x6C4;
		}

		//SSQ_ZONE fix
		if(pUser->pSD->nInSSQ_ZONE && pAttacker->pSD->nInSSQ_ZONE)
		{
			if(pUser->IsInAlliance(pAttacker))
			{
				UINT Relation = grt(pUser, pAttacker);
				Relation |= User::IN_MY_PARTY;

				return Relation;
			}

		}

		//Faction Area Attack Without CTRL
		TerritoryData& td = pUser->pSD->pExData->territoryData;
		TerritoryData& td2 = pAttacker->pSD->pExData->territoryData;

		if(td.territoryId[FACTION_ZONE] != 0)
		{
			if(td2.territoryId[FACTION_ZONE] != 0)
			{
				if( pUser->pED->nFactionID != pAttacker->pED->nFactionID )
				{
					/*UINT relation = grt(pUser, pAttacker);
					relation |= User::KARMA;
					return relation;*/
					return 0x6C4;
				}
			}
		}
	}
		
	return grt(pUser, pAttacker);
}

bool PlayerAction::OnEquipItem(User *pUser, CItem *pItem, int nForce)
{
	typedef bool (__fastcall *_EQI) (User *, CItem *, int);
	_EQI EquipItem = (_EQI) 0x008257C0;

	if(pUser && pItem && pItem->pSID->nItemType & 0xD0000)
		return Hair2Slot::User::EquipItem2(pUser, pItem, nForce); 

	bool bRet = EquipItem(pUser, pItem, nForce);
	CShadowItem::EquipItem(pUser, pItem);

	//Fix2
	DWORD color2 = 0;
	for(map<INT32, DWORD>::iterator it2 = g_ItemNicknameColor2.begin(); it2 != g_ItemNicknameColor2.end(); it2++)
	{
		if( pItem->pSID->nItemID == it2->first )
		{
			color2 = it2->second;
		}
	}

	pUser->pED->WeapontTypeHand = pItem->pSID->nSlotType;
					
	if(color2 != pUser->pED->nicknameColor)
	{
		pUser->pED->nicknameColor = color2;
		pUser->SetUserInfoChanged();
		pUser->SetCharInfoChanged();
	}

	return bRet;
}

bool PlayerAction::OnEnterWorld(User *pUser)
{
	if(pUser->ValidUser())
	{
		bool NoPermitirDosTanquesLogout = false;

		bool MaximoDeTercerasLogout = false;

		if (g_NoPermitirDosTanques)
		{
			int nClass = pUser->pSD->nClass;

 			if (nClass == 6 || nClass == 33 || nClass == 20 || nClass == 5 || nClass == 91 || nClass == 106 || nClass == 99 || nClass == 90)
			{
				int nSubClassIndex = pUser->pSD->nSubClassIndex;

				if (nSubClassIndex != 0 && (pUser->pSD->nSubJobClass[0] == 6 || pUser->pSD->nSubJobClass[0] == 33 || pUser->pSD->nSubJobClass[0] == 20 || pUser->pSD->nSubJobClass[0] == 5 || pUser->pSD->nSubJobClass[0] == 91 || pUser->pSD->nSubJobClass[0] == 106 || pUser->pSD->nSubJobClass[0] == 99 || pUser->pSD->nSubJobClass[0] == 90))
				{
					g_Log.Add(CLog::Error, "[%s] [%S] Tiene dos sub de tanque Dark Avenger, Shillien Knight, Temple Knight o Paladin", __FUNCTION__, pUser->pSD->wszName);
					CSystemMessage msg1(2901);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje. Contacta a un Administrador");
					pUser->pSocket->SendSystemMessage(&msg1);
					NoPermitirDosTanquesLogout = true;
				}
				if (nSubClassIndex != 1 && (pUser->pSD->nSubJobClass[1] == 6 || pUser->pSD->nSubJobClass[1] == 33 || pUser->pSD->nSubJobClass[1] == 20 || pUser->pSD->nSubJobClass[1] == 5 || pUser->pSD->nSubJobClass[1] == 91 || pUser->pSD->nSubJobClass[1] == 106 || pUser->pSD->nSubJobClass[1] == 99 || pUser->pSD->nSubJobClass[1] == 90))
				{
					g_Log.Add(CLog::Error, "[%s] [%S] Tiene dos sub de tanque Dark Avenger, Shillien Knight, Temple Knight o Paladin", __FUNCTION__, pUser->pSD->wszName);
					CSystemMessage msg1(2901);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje. Contacta a un Administrador");
					pUser->pSocket->SendSystemMessage(&msg1);
					NoPermitirDosTanquesLogout = true;
				}
				if (nSubClassIndex != 2 && (pUser->pSD->nSubJobClass[2] == 6 || pUser->pSD->nSubJobClass[2] == 33 || pUser->pSD->nSubJobClass[2] == 20 || pUser->pSD->nSubJobClass[2] == 5 || pUser->pSD->nSubJobClass[2] == 91 || pUser->pSD->nSubJobClass[2] == 106 || pUser->pSD->nSubJobClass[2] == 99 || pUser->pSD->nSubJobClass[2] == 90))
				{
					g_Log.Add(CLog::Error, "[%s] [%S] Tiene dos sub de tanque Dark Avenger, Shillien Knight, Temple Knight o Paladin", __FUNCTION__, pUser->pSD->wszName);
					CSystemMessage msg1(2901);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje. Contacta a un Administrador");
					pUser->pSocket->SendSystemMessage(&msg1);
					NoPermitirDosTanquesLogout = true;
				}
				if (nSubClassIndex != 3 && (pUser->pSD->nSubJobClass[3] == 6 || pUser->pSD->nSubJobClass[3] == 33 || pUser->pSD->nSubJobClass[3] == 20 || pUser->pSD->nSubJobClass[3] == 5 || pUser->pSD->nSubJobClass[3] == 91 || pUser->pSD->nSubJobClass[3] == 106 || pUser->pSD->nSubJobClass[3] == 99 || pUser->pSD->nSubJobClass[3] == 90))
				{
					g_Log.Add(CLog::Error, "[%s] [%S] Tiene dos sub de tanque Dark Avenger, Shillien Knight, Temple Knight o Paladin", __FUNCTION__, pUser->pSD->wszName);
					CSystemMessage msg1(2901);
					msg1.AddText(L"No se pueden mesclar: Dark Avenger, Shillien Knight, Temple Knight o Paladin. En el mismo personaje. Contacta a un Administrador");
					pUser->pSocket->SendSystemMessage(&msg1);
					NoPermitirDosTanquesLogout = true;
				}
			}
		}

		g_UserDB.AddUser(pUser);

		g_DB.RequestLoadCustomSubClass(pUser->nDBID);

		g_DB.RequestLoadNoPKZoneTime(pUser->nDBID);

		

		g_Achivments.OnEnterWorld(pUser);

		pUser->pED->m_CtfUserFlag = 0;

		pUser->SendSystemMessage(g_MensajeEnterWorldServer.c_str());

		g_UserCache.OnEnterWorld(pUser);
		g_SocketDB.SetStatus(pUser->pSocket, CSocketData::IN_WORLD);

		g_CursedWeaponSystem.OnEnterWorld(pUser);
		g_DeathPenalty.ValidatePenalty(pUser);
		
		CItemSP item;
		CItem::FindItemSp(item, pUser->pSD->pExData->hair[0]);
		if(CItem* pItem = item.get())
		{
			if (pItem->pII->itemSkillId > 0)
			{
				pUser->AcquireSkill(pItem->pII->itemSkillId, 1);
				pUser->ValidateAllOnSIM();
			}
		}

		CItemSP item2;
		CItem::FindItemSp(item2, pUser->pSD->pExData->hair[1]);
		if(CItem* pItem2 = item2.get())
		{
			if (pItem2->pII->itemSkillId > 0)
			{
				pUser->AcquireSkill(pItem2->pII->itemSkillId, 1);
				pUser->ValidateAllOnSIM();
			}
		}

		if(g_VisualArmor.IsEnabled())
		{
			g_DB.RequestLoadVisualArmor(pUser->nDBID);
		}

		pUser->SendQuestList();
		ClanSys::EnterWorld(pUser);
		CShadowItem::EnterWorld(pUser);

		SSQSystem::ValidateCpSkill(pUser);

		pUser->pSD->nMaxSlot = 180;

		if(g_Captcha.IsEnabled())
		{
			g_DB.RequestLoadCaptchaInfo(pUser->nDBID);
			//Report Captcha System
			g_DB.RequestLoadCaptchaReportStatus(pUser->nDBID);
		}

		if(g_Jail.IsEnabled())
		{
			g_DB.RequestLoadJailStatus(pUser->nDBID);
		}

		if(g_FractionSystem.IsEnabled())
		{
			g_DB.RequestLoadUserFraction(pUser->nDBID);
		}
		
		if(g_VIPSystem.IsEnabled())
		{
			g_DB.RequestLoadVipStatus(pUser->nDBID);
		}

		if(g_VoteReward.IsEnabled())
		{
			g_DB.RequestLoadVotePoints(pUser->pSocket->accountId, pUser->nDBID);
		}

		if(g_RebirthSystem.Enabled())
		{
			g_DB.RequestLoadRebirth(pUser->nDBID, pUser->pSD->nSubClassIndex);
		}

		if(g_GradePenalty.Enabled())
		{
			g_GradePenalty.Validate(pUser);
		}

		if(g_L2NetworkVote.Enabled())
		{
			UINT type = g_L2NetworkVote.GetIdentityType();
			wstringstream identity;
			switch(type)
			{
			case 0:
				identity << pUser->nDBID;
				break;
			case 1:
				identity << pUser->pSD->wszName;
				break;
			case 2:
				identity << pUser->pSocket->accountId;
				break;
			case 3:
				identity << pUser->pSocket->accountName;
				break;
			}
			if(identity.str().size() > 0)
			{
				g_DB.RequestLoadL2NetworkVote(pUser->nDBID, identity.str().c_str());
			}
		}

		if(g_IndivVote.IsEnabled())
		{
			g_IndivVote.CheckVoteUser(pUser, true);
		}

		if(g_Config.IsSet(CConfig::SKILL_REUSE_MANAGER))
		{
			g_SkillReuseManager.OnEnterWorld(pUser);
		}
		if(g_SchemeBuffer.IsEnabled())
		{
			g_DB.RequestLoadBuffList(pUser->nDBID, pUser->pSD->nSubClassIndex);
		}

		if(g_SaveInstancesOnDB)
			g_DB.RequestLoadInstanceTime(pUser->nDBID);

		pUser->SendETCBuffStatus();

		if(g_ShowInventoryOnEnterWorld)
		{
			pUser->pSD->pExData->TimerHandler.AddTimer(CCreatureTimerHandler::USER_SEND_ITEM_LIST, 4);
		}

		if(g_DailyPvP.IsEnabled())
		{
			g_DB.RequestLoadDailyPvP(pUser->nDBID);
		}

		if(g_SubStack.IsEnabled())
		{
			g_DB.RequestLoadSubStack(pUser->nDBID);
		}

		if(g_EventStats.IsEnabled())
		{
			g_DB.RequestLoadEventStats(pUser->nDBID);
		}

		g_PvPEvents.RequestLoadPvPEventUserVars(pUser->nDBID);


		if(g_Config.IsSet(CConfig::SPIRIT_SYSTEM))
		{
			g_SpiritSystem.ValidateSkill(pUser);
			g_DB.RequestLoadSpiritCount(pUser->nDBID);
		}
		if(g_Config.IsSet(CConfig::ERA_SYSTEM))
			pUser->pSD->pExData->TimerHandler.AddTimer(CCreatureTimerHandler::USER_SEND_ERA_MOON, 2);
		
		if(g_AIOSystem.IsEnabled())
			g_DB.RequestLoadAIO(pUser->nDBID);
		if(g_ValidateAcquiredSkills)
			pUser->pSD->pExData->TimerHandler.AddTimer(CCreatureTimerHandler::USER_VALIDATE_ACQUIRED_SKILLS, 2);
		
		if(g_Config.IsSet(CConfig::ITEM_REUSE_MANAGER))
		{
			pUser->pSD->pExData->TimerHandler.AddTimer(CCreatureTimerHandler::VALIDATE_ITEM_REUSE, 3);
		}

		if(g_AutoLoot.IsEnabled() && g_AutoLoot.IsActiveByDefault())
		{
			pUser->pED->autoLoot = true;
		}

		g_Wedding.OnLoad(pUser);
		g_DB.RequestLoadNameTitleColor(pUser->nDBID);
		if(g_CharacterLock.IsEnabled())
		{
			g_DB.RequestLoadCharacterLock(pUser->nDBID);
		}

		g_AutoAnnounce.OnEnterWorld(pUser);
		pUser->SendLifeTimeItemsInfo();

		//New Builder Skills Add

		if( m_BuilderSkills && pUser->pSD->nBuilder )
		{
			pUser->AcquireSkill(7041, 1); //Master's Blessing - Focus
			pUser->AcquireSkill(7042, 1); //Master's Blessing - Death Whisper
			pUser->AcquireSkill(7043, 1); //Master's Blessing - Haste
			pUser->AcquireSkill(7044, 1); //Master's Blessing - Guidance
			pUser->AcquireSkill(7045, 1); //Master's Blessing - Blessed Body
			pUser->AcquireSkill(7046, 1); //Master's Blessing - Blessed Soul
			pUser->AcquireSkill(7047, 1); //Master's Blessing - Agility
			pUser->AcquireSkill(7048, 1); //Master's Blessing - Acumen
			pUser->AcquireSkill(7049, 1); //Master's Blessing - Decrease Weight
			pUser->AcquireSkill(7050, 1); //Master's Blessing - Might
			pUser->AcquireSkill(7051, 1); //Master's Blessing - Shield
			pUser->AcquireSkill(7052, 1); //Master's Blessing - Magic Barrier
			pUser->AcquireSkill(7053, 1); //Master's Blessing - Vampiric Rage
			pUser->AcquireSkill(7054, 1); //Master's Blessing - Empower
			pUser->AcquireSkill(7055, 1); //Master's Blessing - Wind Walk
			pUser->AcquireSkill(7056, 1); //Master's Blessing - Berserker Spirit
			pUser->AcquireSkill(7057, 1); //Master's Blessing - Greater Might
			pUser->AcquireSkill(7058, 1); //Master's Blessing - Greater Shield
			pUser->AcquireSkill(7059, 1); //Master's Blessing - Wild Magic
			pUser->AcquireSkill(7060, 1); //Master's Blessing - Clarity
			pUser->AcquireSkill(7061, 1); //Master's Blessing - Prophecy of Water
			pUser->AcquireSkill(7062, 1); //Master's Blessing - Prophecy of Fire
			pUser->AcquireSkill(7063, 1); //Master's Blessing - Prophecy of Wind
			pUser->AcquireSkill(7064, 1); //Master's Blessing - Chant of Victory
			//pUser->AcquireSkill(11515, 1); //GM Foss 1
			//pUser->AcquireSkill(11516, 1); //GM Foss 2
			//pUser->AcquireSkill(11517, 1); //GM Cancel
			pUser->ValidateParameters();
		}

		if(g_CliExt.IsEnabled())
		{
			char sHwid[33];
			memset(sHwid, 0, 33);
			memcpy(sHwid, pUser->pSocket->pED->longHWID.hash, 32);
			g_Logger.Add(L"Enter world user[%s][%d] account[%s][%d] ip[%d.%d.%d.%d] HWID[%S]", pUser->pSD->wszName, pUser->nDBID, pUser->pSocket->accountName, pUser->pSocket->accountId, pUser->pSocket->addr.S_un.S_un_b.s_b1, pUser->pSocket->addr.S_un.S_un_b.s_b2, pUser->pSocket->addr.S_un.S_un_b.s_b3, pUser->pSocket->addr.S_un.S_un_b.s_b4, sHwid);
			g_DB.RequestSaveHardwareId(pUser->nDBID, pUser->pSocket->pED->longHWID.hash);

			if (pUser->GetSocket()->pED->IsLoadOfflineShop == 0)
				g_DB.RequestSaveHardwareIdString(pUser->nDBID, pUser->pSocket->pED->hwidString);

			if(g_CliExt.GetVersion() >= 7)
			{
				//Job packet
				//                        \Device\NamedPipe\CF3614CF075AA0CB
				//pUser->pSocket->Send("cddS", 0x87, 11, 1, L"CF3614CF075AA0CB");
			}


			if(BienvenidoNuevoPersonaje)
			{
				if(pUser->pSD->nLevel == 1)
				{
					if (find(Hwids.begin(), Hwids.end(), pUser->pSocket->pED->longHWID.ToWchar()) != Hwids.end()) {
						
					} else {
						Hwids.push_back(pUser->pSocket->pED->longHWID.ToWchar());

						wstring m_Message = BienvenidoNuevoPersonajeMsg;
						wstring personajename = pUser->pSD->wszName;
						size_t pos = m_Message.find(L"$charName");
						while(pos != wstring::npos)
						{
							m_Message = m_Message.replace(pos, 9, personajename);
							pos = m_Message.find(L"$charName");
						}

						Utils::BroadcastToAllUser_Announce(m_Message.c_str());
					}
				}
			}

			if(g_CliExt.m_EnabledAntiAdrenaline)
			{
				pUser->pSocket->Send("cddSS", 0x87, 15, 1, g_CliExt.GetPatternName(), g_CliExt.GetPatternMask());
				pUser->pSocket->Send("cddSS", 0x87, 15, 1, g_CliExt.GetPatternName2(), g_CliExt.GetPatternMask2());
			//	pUser->pSocket->Send("cddSS", 0x87, 15, 1, L"adre   nalin   ebot.com", L"xxxxxxxxxxxxxxx");
			}

		}else
		{
			g_Logger.Add(L"Enter world user[%s][%d] account[%s][%d] ip[%d.%d.%d.%d]", pUser->pSD->wszName, pUser->nDBID, pUser->pSocket->accountName, pUser->pSocket->accountId, pUser->pSocket->addr.S_un.S_un_b.s_b1, pUser->pSocket->addr.S_un.S_un_b.s_b2, pUser->pSocket->addr.S_un.S_un_b.s_b3, pUser->pSocket->addr.S_un.S_un_b.s_b4);
		}

		pUser->ChangeTarget(NULL, true);
		if(g_ShowEnterWorldHtml)
		{
			const WCHAR* pFile = g_HtmlCache.Get(L"enterworld.htm");
			
			if(pFile)
			{
				PlayerAction::ShowHTML(pUser, L"enterworld.htm", pFile, 40000);
			}
		}




		if(int territoryId = g_TerritoryChecker.IsInTerritory(pUser, NO_RESTART_ZONE))
		{
			if(CNoRestartTerritory* pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastNoRestart())
			{
				IVector kickLoc = pTerritory->GetKickOutLocation();
				pUser->SendSystemMessage(L"You cannot login in here!");
				PlayerAction::OnTeleportToLocation(pUser, kickLoc.x, kickLoc.y, kickLoc.z, 0);
			}
		}

		/*if( pUser->pSD->nHero == 2 )
		{
			//Hero Enter Announcer
			wstring announce = Utils::ReplaceString(L"Hero <[param]>, just logged on server!", _T("[param]"), pUser->pSD->wszName);
			CHAR pck[8190];
			int nSize = Assemble(pck, 8190, "cddSS", 0x4A, 0, 18, L"", announce.c_str());
			L2Server::BroadcastToAllUser(nSize, pck);
		}*/

		//Check if player is inside tvt event.
		//g_TvT.CheckPlayerLogin(pUser);

		if(g_TerritoryChecker.IsInTerritory(pUser, NOCHARSHOWZONE))
		{
			//IVector kickOut = pT->GetKickOutPos();
			PlayerAction::OnTeleportToLocation(pUser, pUser->pSD->Pos.x, pUser->pSD->Pos.y, pUser->pSD->Pos.z, 0);
		}

		pUser->QuitarSkillDeTerceraDeLasOtrasClases();
		pUser->AutoSkills();



		g_Championship.OnEnterWorld(pUser);


		if(pUser->pSD->nBuilder)
		{
			if (g_Config_GM_Login_Undying)
			{		
				CCreature *pCreature = pUser->CastCreature();
				pCreature->WriteLock(__FILEW__, __LINE__);
				pUser->pSD->bUndying = 1;
				pCreature->WriteUnlock();
			}
			if (g_Config_GM_Login_UnHide)
			{		
				CCreature *pCreature = pUser->CastCreature();
				pCreature->WriteLock(__FILEW__, __LINE__);
				pUser->pSD->bHide = 0;
				pCreature->WriteUnlock();
				PlayerAction::OnTeleportToLocation(pUser, pUser->pSD->Pos.x, pUser->pSD->Pos.y, pUser->pSD->Pos.z, 0);
			}
		}


		g_RatesDinamicos.EnterWorld(pUser);

		if(NoPermitirDosTanquesLogout)
			pUser->pSocket->Close();


		int count = 0;
		if(pUser->pSD->nSubJobClass[0] > 80)
			count++;

		if(pUser->pSD->nSubJobClass[1] > 80)
			count++;

		if(pUser->pSD->nSubJobClass[2] > 80)
			count++;

		if(pUser->pSD->nSubJobClass[3] > 80)
			count++;



		if(pUser->pED->nCustomSubClass[0] > 80)
			count++;

		if(pUser->pED->nCustomSubClass[1] > 80)
			count++;

		if(pUser->pED->nCustomSubClass[2] > 80)
			count++;

		if(pUser->pED->nCustomSubClass[3] > 80)
			count++;



		if(count > g_MaximoDeTercerasLogout && !pUser->pSD->nBuilder)
			pUser->pSocket->Close();


		if (g_achiv)
			g_Achivments.VerificarParaCobrar(pUser);


//		pUser->pSocket->Send("ccccccccccccccccccccccccccccccc",0xFE, 0x2E, 0x00, 0xFA, 0x00, 0x00, 0x00, 0x96, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00);
//		pUser->pSocket->Send("ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",0x1B, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x7B, 0x13, 0xAF, 0x10, 0x39, 0x00, 0x00, 0x00, 0xCE, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x12, 0xF0, 0xAE, 0x10, 0x41, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x0B, 0xF0, 0xAE, 0x10, 0x7A, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x09, 0xF0, 0xAE, 0x10, 0x7B, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF);
//		pUser->pSocket->Send("ccccccccccccccccc", 0x2A, 0x01, 0xF0, 0xAE, 0x10, 0x65, 0xE9, 0xFE, 0xFF, 0xC8, 0xF0, 0x03, 0x00, 0xDB, 0xF3, 0xFF, 0xFF); 

	}else
		g_Log.Add(CLog::Error, "[%s] NULL User!!!", __FUNCTION__);
	//Normal Execution
	return pUser->SendCoolTime();
}

bool PlayerAction::OnPvPFlag(User *pUser, bool c)
{
	if(pUser->ValidUser())
	{
		TerritoryData& td = pUser->pSD->pExData->territoryData;
		if(td.territoryId[FACTION_ZONE] != 0)
		{
			c = false;
		}
	}

	typedef bool (*f)(User*, bool);
	return f(0x815030L)(pUser, c);
}

bool PlayerAction::OnDropItem(User *pUser, CItem *pItem, int nAmount, FVector *pPos)
{
	if(pItem->IsValidItem())
	{
		if(pItem->nAugmentationID)
			return false;

		if(pItem->nProtectionTimeout > time(NULL))
		{
			if(pUser->ValidUser())
			{
				pUser->SendSystemMessage(L"This item is protected and cannot be dropped!");
			}
			return false;
		}

		if(pUser->ValidUser())
		{
			TerritoryData& td = pUser->pSD->pExData->territoryData;
			if(td.territoryId[NO_DROP_ITEM_ZONE] != 0)
			{
				pUser->SendSystemMessage(L"You cannot drop items here.");
				return false;
			}
		}

	}

	typedef bool ( * f)(User*, CItem*, int, FVector*);
	return f(0x800350L)(pUser, pItem, nAmount, pPos);
}

bool PlayerAction::OnDie(User *pUser, CCreature *pEnemy)
{
	typedef bool (__fastcall *_UD)(User*, CCreature*);
	_UD UD = (_UD) 0x0081DF00;

	if(pUser->pSD->pExData)
	{
		pUser->TimerExpiredForHiddenAbnormals(true);
		pUser->DispelByAbnormal(181, true);
	}

	if(g_DuelSystem.Die(pUser))
	{
		return false;
	}

	g_CursedWeaponSystem.OnDie(pUser, pEnemy);
	
	bool selfResurrection = false;
	if(pUser->pSD->pExData && pUser->pSD->pExData->SkillMod.nSelfResurrection)
	{
		selfResurrection = true;
	}

	
	g_TvT.OnDie(pUser, pEnemy);
	g_Championship.OnDie(pUser);

	g_PvPEvents.OnDie(pUser, pEnemy, false);


	g_TerritoryChecker.Die(pUser);


	if(pEnemy->ValidUser())
	{
		if(pUser->SafeCastUser()->killDamageType == 6)
			pEnemy->SafeCastUser()->pED->nNoSumarPVPniPk = true;


		if(pEnemy->SafeCastUser()->pED->tvtUser.status == TvT::UserFighting)
			pEnemy->SafeCastUser()->pED->nNoSumarPVPniPk = true;

		if(g_DailyPvP.IsEnabled() && !pEnemy->SafeCastUser()->pED->nNoSumarPVPniPk)
		{
			if(pEnemy->ValidUser() || pEnemy->IsSummon())
			{
				if(pEnemy->IsSummon())
				{
					if(!g_DailyPvP.GetPoint(pEnemy->CastSummon()->GetMaster(), pUser))
						pEnemy->CastSummon()->GetMaster()->pED->nNoSumarPVPniPk = true;
				}else
				{
					if(!g_DailyPvP.GetPoint(pEnemy->SafeCastUser(), pUser))
						pEnemy->SafeCastUser()->pED->nNoSumarPVPniPk = true;
				}
			}
		}


		//PVP_ZONE_STEAL
		int territoryId = pUser->pSD->pExData->territoryData.territoryId[PVP_ZONE_STEAL];
		if(territoryId != 0)
		{
			User *pEnemyUser = 0;
			if(pEnemy->ValidUser())
			{
				pEnemyUser = pEnemy->GetUser();
			}
			if(pEnemy->IsSummon())
			{
				pEnemyUser = pEnemy->CastSummon()->GetMaster();
			}
				
			if(pEnemyUser->ValidUser())
			{
				if(pUser->pED->nInPvpZoneSteal && pEnemyUser->pED->nInPvpZoneSteal)
				{
					CPvPZoneStealTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastPvPZoneSteal();
					if(pTerritory)
					{
						pTerritory->Handle(pUser, pEnemyUser);
					}
				}
			}
		}

		//|| g_TvT.m_SumarPvPReward
		if(!pEnemy->SafeCastUser()->pED->nNoSumarPVPniPk)
		{
			//PvP Reward zone
			int territoryId = pUser->pSD->pExData->territoryData.territoryId[PVP_REWARD_ZONE];
			if(territoryId != 0)
			{
				User *pEnemyUser = 0;
				if(pEnemy->ValidUser())
				{
					pEnemyUser = pEnemy->GetUser();
				}
				if(pEnemy->IsSummon())
				{
					pEnemyUser = pEnemy->CastSummon()->GetMaster();
				}

				if(pEnemyUser->ValidUser())
				{
					bool inWar = false;
					if(pUser->pSD->nPledgeID > 0 && pEnemyUser->pSD->nPledgeID > 0 && pUser->pSD->nPledgeID != pEnemyUser->pSD->nPledgeID)
					{
						if(CPledge *pPledge = pUser->GetPledge())
						{
							if(pPledge->IsInWarWithEx(pEnemyUser->pledgeServerId))
							{
								inWar = true;
							}
						}
					}
					if(pUser->pSD->bGuilty || pUser->pSD->nInCustomPvpZone || inWar || pUser->pED->nInFactionPvpZone)
					{
						CPvPRewardTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastPvPReward();
						if(pTerritory)
						{
							pTerritory->Handle(pUser, pEnemyUser);
						}
					}
				}
			}

			//War Reward zone
			territoryId = pUser->pSD->pExData->territoryData.territoryId[WAR_REWARD_ZONE];
			if(territoryId != 0)
			{
				User *pEnemyUser = 0;
				if(pEnemy->ValidUser())
				{
					pEnemyUser = pEnemy->GetUser();
				}
				if(pEnemy->IsSummon())
				{
					pEnemyUser = pEnemy->CastSummon()->GetMaster();
				}
				
				if(pEnemyUser->ValidUser())
				{
					if(pUser->pED->tvtUser.status != TvT::UserFighting && pEnemyUser->pED->tvtUser.status != TvT::UserFighting)
					{
						bool inWar = false;
						if(pUser->pSD->nPledgeID > 0 && pEnemyUser->pSD->nPledgeID > 0 && pUser->pSD->nPledgeID != pEnemyUser->pSD->nPledgeID)
						{
							if(CPledge *pPledge = pUser->GetPledge())
							{
								if(pPledge->IsInWarWithEx(pEnemyUser->pledgeServerId))
								{
									inWar = true;
								}
							}
						}
						if(inWar)
						{
							CWarRewardTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastWarReward();
							if(pTerritory)
							{
								pTerritory->Handle(pUser, pEnemyUser);
							}
						}
					}
				}
			}

			//War Reward Zone
			territoryId = pUser->pSD->pExData->territoryData.territoryId[PK_REWARD_ZONE];
			if(territoryId != 0)
			{
				User *pEnemyUser = 0;
				if(pEnemy->ValidUser())
				{
					pEnemyUser = pEnemy->GetUser();
				}
				if(pEnemy->IsSummon())
				{
					pEnemyUser = pEnemy->CastSummon()->GetMaster();
				}
				
				if(pEnemyUser->ValidUser())
				{
					if(pUser->pED->tvtUser.status != TvT::UserFighting && pEnemyUser->pED->tvtUser.status != TvT::UserFighting)
					{
						bool inWar = false;
						if(pUser->pSD->nPledgeID > 0 && pEnemyUser->pSD->nPledgeID > 0 && pUser->pSD->nPledgeID != pEnemyUser->pSD->nPledgeID)
						{
							if(CPledge *pPledge = pUser->GetPledge())
							{
								if(pPledge->IsInWarWithEx(pEnemyUser->pledgeServerId))
								{
									inWar = true;
								}
							}
						}
						if(!inWar && !pUser->pSD->nInBattleField && !pUser->pSD->bGuilty)
						{
							CPkRewardTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastPkReward();
							if(pTerritory)
							{
								pTerritory->Handle(pUser, pEnemyUser);
							}
						}
					}
				}
			}

			if(g_Config.IsSet(CConfig::KILL_DEATH_STAT))
				g_KillDeathStat.OnUserDie(pUser, pEnemy);

			if(g_Config.IsSet(CConfig::SPIRIT_SYSTEM))
				g_SpiritSystem.OnHunt(pEnemy, pUser);

			if(g_Config.IsSet(CConfig::SIEGE_REPORT))
			{
				if(pUser->pSD->nPledgeID)
				{
					FVector Pos = pUser->pSD->Pos;
					int Killer = 0;
					int PledgeK = 0;
					int Owned = pUser->nDBID;
					int PledgeO = pUser->pSD->nPledgeID;
					
					if(pEnemy->ValidUser())
					{
						Killer = pEnemy->nDBID;
						PledgeK = pEnemy->pSD->nPledgeID;
					}
					else if(pEnemy->IsSummon())
					{
						User *pMaster = pEnemy->CastSummon()->GetMaster();
						if(pMaster->ValidUser())
						{
							Killer = pMaster->nDBID;
							PledgeK = pMaster->pSD->nPledgeID;
						}
					}
					if(Killer && PledgeO)
					{
						CSiegeStat::GetInstance().ReportKillDeathCount(Pos, Killer, PledgeK, Owned, PledgeO);
					}
				}
			}
		}




		//NOPK Zone
		territoryId = pUser->pSD->pExData->territoryData.territoryId[NOPKZONE];
		if(territoryId != 0)
		{
			User *pEnemyUser = 0;
			if(pEnemy->ValidUser())
			{
				pEnemyUser = pEnemy->GetUser();
			}
			if(pEnemy->IsSummon())
			{
				pEnemyUser = pEnemy->CastSummon()->GetMaster();
			}
				
			if(pEnemyUser->ValidUser())
			{
				if(pUser->pED->tvtUser.status != TvT::UserFighting && pEnemyUser->pED->tvtUser.status != TvT::UserFighting)
				{
					bool inWar = false;
					if(pUser->pSD->nPledgeID > 0 && pEnemyUser->pSD->nPledgeID > 0 && pUser->pSD->nPledgeID != pEnemyUser->pSD->nPledgeID)
					{
						if(CPledge *pPledge = pUser->GetPledge())
						{
							if(pPledge->IsInWarWithEx(pEnemyUser->pledgeServerId))
							{
								inWar = true;
							}
						}
					}
					if(!inWar && !pUser->pSD->nInBattleField && !pUser->pSD->bGuilty)
					{
						CNoPKZoneTerritory *pTerritory = g_TerritoryChecker.GetTerritory(territoryId)->SafeCastNoPKZone();
						if(pTerritory)
						{
							pTerritory->Handle(pUser, pEnemyUser);
						}
					}
				}
			}
		}
	}

	if(UD(pUser, pEnemy))
	{
		if(pEnemy->ValidUser())
		{
			if(User *pEnemyUser2 = pEnemy->GetResponsibleUser())
				{
				if (!pEnemyUser2->pSD->nKarma)
				{
					if(!pEnemyUser2->SafeCastUser()->pED->nNoSumarPVPniPk)
						g_Achivments.SetUser_PvP(pEnemyUser2);
				}
			}
		}

		if(pUser->pED->charmOfCourageLevel > 0)
		{
			pUser->pED->charmOfCourageLevel = 0;
			pUser->SendETCBuffStatus();
		}

		if(pUser->ValidUser() && pEnemy->ValidUser())
		{
			TerritoryData& td = pUser->pSD->pExData->territoryData;
			TerritoryData& td2 = pEnemy->pSD->pExData->territoryData;

			if( (td.territoryId[FACTION_ZONE] != 0) && (td2.territoryId[FACTION_ZONE] != 0) )
			{
				//nothing
			}
			else
			{
				ClanSys::Die(pUser, pEnemy); //maybe bug with summons? it checks the valid users
			}
		}

		if(User *pEnemyUser = pEnemy->GetResponsibleUser())
		{
			PvP::CPvPAnnounce& pvpAnn = PvP::CPvPAnnounce::GetInstance();
			if(pvpAnn.Enabled())
			{
				pvpAnn.OnKill(pEnemyUser, pUser, pEnemyUser->pSD->nKarma ? true : false, (pUser->pSD->nInBattleField || pUser->pSD->nInCustomPvpZone || pUser->pED->nInFactionPvpZone) );
			}

//			if( pUser->pSD->nInCustomPvpZone && pUser->IsInAlliance(pEnemyUser))
//			{
//				pEnemyUser->IncreaseDuelCount();
//			}

			pEnemyUser->SetUserInfoChanged();
		}

//		if(g_DailyPvP.IsEnabled())
//		{
//			if(pEnemy->ValidUser() || pEnemy->IsSummon())
//			{
//				if(pEnemy->IsSummon())
//				{
//					g_DailyPvP.GetPoint(pEnemy->CastSummon()->GetMaster(), pUser);
//				}else
//				{
//					g_DailyPvP.GetPoint(pEnemy->SafeCastUser(), pUser);
//				}
//			}
//		}
	
		if(pEnemy->IsMob())
		{
			g_DeathPenalty.OnDieByMob(pUser);
		}

		g_FractionSystem.OnDie(pUser, pEnemy);

		if(selfResurrection)
		{
			pUser->DispelByAbnormal(188, true);
			CSkillInfo *pSI = g_SkillDB.GetSkillInfo(2049, 1); //Bres
			if(pSI)
			{
				pSI->ActivateSkill(pUser, pUser, 0, 0);
			}
		}

		if(pEnemy->ValidUser())
		{
			pEnemy->SafeCastUser()->pED->nNoSumarPVPniPk = false;
		}

		return true;
	}

	if(pEnemy->ValidUser())
	{
		pEnemy->SafeCastUser()->pED->nNoSumarPVPniPk = false;
	}

	return false;
}


void PlayerAction::OnChangeSubjobEnd(User *pUser, bool bCreate)
{
	guard;

	typedef void (*f)(User*, bool);
	f(0x854050L)(pUser, bCreate);

	if(pUser->ValidUser())
	{
		g_DeathPenalty.ValidatePenalty(pUser);
	
		if(g_ArmorPenalty.IsEnabled())
		{
			pUser->pSD->pExData->ArmorPenalty = false;
			g_ArmorPenalty.Validate(pUser);
		}
		
		if(g_SchemeBuffer.IsEnabled())
		{
			g_DB.RequestLoadBuffList(pUser->nDBID, pUser->pSD->nSubClassIndex);
		}

		if(pUser->pSD->nCursedOwner)
		{
			//Acquire skills
			g_CursedWeaponSystem.OnChangeSubjob(pUser);
		}
		if(pUser->pSD->pExData)
		{
			pUser->ClearHiddenAbnormals();
			pUser->pSD->pExData->HerbAbnormalMgr.Clear(-1);
		}
		if(pUser->pED)
		{
			pUser->pED->lock.Enter();
			pUser->pED->itemSkills.clear();
			pUser->pED->lock.Leave();
		}

		if(g_RebirthSystem.Enabled())
		{
			RebirthUser& ru = pUser->pED->rebirthUser;
			ru.availablePoints = ru.bonusCon = ru.bonusDex = ru.bonusInt = ru.bonusMen = ru.bonusStr = ru.bonusWit = ru.rebirthCount = 0;
			g_DB.RequestLoadRebirth(pUser->nDBID, pUser->pSD->nSubClassIndex);
		}

		if(g_Config.IsSet(CConfig::SPIRIT_SYSTEM))
		{
			g_SpiritSystem.ValidateSkill(pUser);
		}

		
		if(g_GradePenalty.Enabled())
		{
			g_GradePenalty.Validate(pUser);
		}

		pUser->ValidateEquippedItems();

		SSQSystem::ValidateCpSkill(pUser);

		if(g_ValidateAcquiredSkills)
			pUser->ValidateAcquiredSkills();

		if(CPledge *pPledge = pUser->GetPledge())
		{
			pPledge->AcquirePledgeSkills(pUser);
		}

		pUser->ValidateAllOnWeapon();
		pUser->requestSaveCharacterInfoTick = 195;
		g_DB.RequestSaveSubjob(pUser->nDBID, pUser->pSD->nSubClassIndex, pUser->pSD->fHP, pUser->pSD->fMP, pUser->pSD->nExp, pUser->pSD->nSp, pUser->pSD->nLevel, pUser->pSD->nHenna1, pUser->pSD->nHenna2, pUser->pSD->nHenna3);

		pUser->AutoSkills();
		pUser->QuitarSkillDeTerceraDeLasOtrasClases();

	}

	unguard;
}

void PlayerAction::OnCreateSubjobEnd(User *pUser, bool bCreate)
{
	guard;

	typedef void (*f)(User*, bool);
	f(0x854050L)(pUser, bCreate);

	if(pUser->ValidUser())
	{
		g_DeathPenalty.ValidatePenalty(pUser);
	
		if(g_ArmorPenalty.IsEnabled())
		{
			pUser->pSD->pExData->ArmorPenalty = false;
			g_ArmorPenalty.Validate(pUser);
		}
		
		if(g_SchemeBuffer.IsEnabled())
		{
			g_DB.RequestLoadBuffList(pUser->nDBID, pUser->pSD->nSubClassIndex);
		}

		if(pUser->pSD->nCursedOwner)
		{
			//Acquire skills
			g_CursedWeaponSystem.OnChangeSubjob(pUser);
		}
		if(pUser->pSD->pExData)
		{
			pUser->ClearHiddenAbnormals();
			pUser->pSD->pExData->HerbAbnormalMgr.Clear(-1);
		}
		if(pUser->pED)
		{
			pUser->pED->lock.Enter();
			pUser->pED->itemSkills.clear();
			pUser->pED->lock.Leave();
		}

		if(g_RebirthSystem.Enabled())
		{
			RebirthUser& ru = pUser->pED->rebirthUser;
			ru.availablePoints = ru.bonusCon = ru.bonusDex = ru.bonusInt = ru.bonusMen = ru.bonusStr = ru.bonusWit = ru.rebirthCount = 0;
			g_DB.RequestLoadRebirth(pUser->nDBID, pUser->pSD->nSubClassIndex);
		}

		if(g_Config.IsSet(CConfig::SPIRIT_SYSTEM))
		{
			g_SpiritSystem.ValidateSkill(pUser);
		}

		
		if(g_GradePenalty.Enabled())
		{
			g_GradePenalty.Validate(pUser);
		}

		pUser->ValidateEquippedItems();

		SSQSystem::ValidateCpSkill(pUser);

		if(g_ValidateAcquiredSkills)
			pUser->ValidateAcquiredSkills();

		if(CPledge *pPledge = pUser->GetPledge())
		{
			pPledge->AcquirePledgeSkills(pUser);
		}

		pUser->ValidateAllOnWeapon();
		pUser->requestSaveCharacterInfoTick = 195;
		g_DB.RequestSaveSubjob(pUser->nDBID, pUser->pSD->nSubClassIndex, pUser->pSD->fHP, pUser->pSD->fMP, pUser->pSD->nExp, pUser->pSD->nSp, pUser->pSD->nLevel, pUser->pSD->nHenna1, pUser->pSD->nHenna2, pUser->pSD->nHenna3);

		pUser->AutoSkills();
		pUser->QuitarSkillDeTerceraDeLasOtrasClases();


		if (g_AnnounceSubClass)
		{
			if (pUser->pSD->nSubClassIndex == 1)
			{
				tstring announce = g_AnnounceSubClassMsg1;
				announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
				Utils::BroadcastToAllUser_Announce(announce.c_str());
			}
			else if (pUser->pSD->nSubClassIndex == 2)
			{
				tstring announce = g_AnnounceSubClassMsg2;
				announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
				Utils::BroadcastToAllUser_Announce(announce.c_str());
			}
			else if (pUser->pSD->nSubClassIndex == 3)
			{
				tstring announce = g_AnnounceSubClassMsg3;
				announce = Utils::ReplaceString(announce, _T("[player_name]"), pUser->pSD->wszName, true);
				Utils::BroadcastToAllUser_Announce(announce.c_str());

				if(m_TerminarPersonajeRewardId > 0 && m_TerminarPersonajeRewardAmount > 0)
				{
						pUser->AddItemToInventory(m_TerminarPersonajeRewardId, m_TerminarPersonajeRewardAmount);
				}
			}
		}
	}

	unguard;
}

void PlayerAction::OnChangeSubjobBegin(User *pUser)
{
	guard;

	if(g_SchemeBuffer.IsEnabled())
	{
		g_DB.RequestSaveBuffList(pUser);
		pUser->ClearQueuedBuffs();
	}

	pUser->pSD->pExData->SummonFriend.Clear();

	if(pUser->pSD->DuelInfo.DuelID)
	{
		g_DuelSystem.Interrupt(pUser->pSD->DuelInfo.DuelID);
	}

	if(g_InfinityShot.IsEnabled())
	{
		g_InfinityShot.AutoOff(pUser);
	}

	if(g_SpiritShotExtension)
	{
		g_InfinityShot.AutoOff_Normal(pUser);
	}
	g_DB.RequestSaveCharacterInfo(pUser, true, false);

	typedef void (*f)(User*);
	f(0x851230)(pUser);

	unguard;
}

bool PlayerAction::COlympiadEntry_RemoveEntry(LPVOID pInstance, UINT userId)
{
	typedef bool (*f)(LPVOID, UINT);
	return f(0x708160L)(pInstance, userId);
}

bool PlayerAction::COlympiadEntry_AddEntry(LPVOID pInstance, UINT userId, bool bClassFree)
{
	typedef bool (*f)(LPVOID, UINT, bool);

	if(!COlympiadSystem::IsFightEnabled(bClassFree))
	{
		if(User *pUser = User::GetUserBySID(&userId))
		{
			if(bClassFree)
			{
				pUser->SendSystemMessage(L"The class free fights are disabled today.");
			}else
			{
				pUser->SendSystemMessage(L"The class fights are disabled today.");
			}
		}
		return false;
	}

	if(f(0x70CAA0L)(pInstance, userId, bClassFree))
	{
		return true;
	}
	return false;
}
