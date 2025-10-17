#include "stdafx.h"
#include "ScriptAccessible.h"

void CScriptAccessible::Init()
{
	ExtendGlobalObjectFunctionArray();
}

//base 16 functions + 1 ending line with 0
//AiFunction g_GlobalObjectFunctionArray[21+1];
AiFunction g_GlobalObjectFunctionArray[26+1];

const WCHAR* g_TeleportMPCC = L"TeleportMPCC";
const WCHAR* g_TeleportMPCCByIndex = L"TeleportMPCCByIndex";
const WCHAR* g_SetPCLevel = L"SetPCLevel";
const WCHAR* g_AddPCSocial = L"AddPCSocial";
const WCHAR* g_UpdatePledgeNameValue = L"UpdatePledgeNameValue";
const WCHAR* g_FlagUser = L"FlagUser";
const WCHAR* g_TvTEvent = L"TvTEvent";
const WCHAR* g_BlueFlagEvent = L"BlueFlagEvent";
const WCHAR* g_RedFlagEvent = L"RedFlagEvent";
const WCHAR* g_StopEvent = L"StopEvent";
const WCHAR* g_CastBuffForQuestReward = L"CastBuffForQuestReward2";




void CScriptAccessible::ExtendGlobalObjectFunctionArray()
{
	memset(g_GlobalObjectFunctionArray, 0, sizeof(g_GlobalObjectFunctionArray));
	//load existing data
	memcpy(g_GlobalObjectFunctionArray, (LPVOID)0x77CFA0, 16*120);
	
	UINT index = 16;
	//Addr 0xD040010 - 218365968
	AiFunction& func = g_GlobalObjectFunctionArray[index];
	func.wName = g_TeleportMPCC;
	func.handler = CGlobalObject::TeleportMPCC;
	func.returnType = AI_TYPE_VOID;
	func.paramCount = 4;
	func.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func.param2Type = AI_TYPE_INT;
	func.param3Type = AI_TYPE_INT;
	func.param4Type = AI_TYPE_INT;
	index++;
	//0xD050011 - 218431505
	AiFunction& func2 = g_GlobalObjectFunctionArray[index];
	func2.wName = g_TeleportMPCCByIndex;
	func2.handler = CGlobalObject::TeleportMPCCByIndex;
	func2.returnType = AI_TYPE_VOID;
	func2.paramCount = 5;
	func2.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func2.param2Type = AI_TYPE_INT;
	func2.param3Type = AI_TYPE_INT;
	func2.param4Type = AI_TYPE_INT;
	func2.param5Type = AI_TYPE_INT;
	index++;
	//0xD020012 - 218234898
	AiFunction& func3 = g_GlobalObjectFunctionArray[index];
	func3.wName = g_SetPCLevel;
	func3.handler = CGlobalObject::SetPCLevel;
	func3.returnType = AI_TYPE_VOID;
	func3.paramCount = 2;
	func3.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func3.param2Type = AI_TYPE_INT;
	index++;
	//0xD020013 - 218234899
	AiFunction& func4 = g_GlobalObjectFunctionArray[index];
	func4.wName = g_AddPCSocial;
	func4.handler = CGlobalObject::AddPCSocial;
	func4.returnType = AI_TYPE_VOID;
	func4.paramCount = 2;
	func4.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func4.param2Type = AI_TYPE_INT;
	index++;
	//0xD020014 - 218234900
	AiFunction& func5 = g_GlobalObjectFunctionArray[index];
	func5.wName = g_UpdatePledgeNameValue;
	func5.handler = CGlobalObject::UpdatePledgeNameValue;
	func5.returnType = AI_TYPE_VOID;
	func5.paramCount = 2;
	func5.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func5.param2Type = AI_TYPE_INT;
	index++;

	//0xD020015 - 218234901
	AiFunction& func6 = g_GlobalObjectFunctionArray[index];
	func6.wName = g_FlagUser;
	func6.handler = CGlobalObject::FlagUser;
	func6.returnType = AI_TYPE_VOID;
	func6.paramCount = 2;
	func6.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func6.param2Type = AI_TYPE_INT;
	index++;
	//0xD020016 - 218234902
	AiFunction& func7 = g_GlobalObjectFunctionArray[index];
	func7.wName = g_TvTEvent;
	func7.handler = CGlobalObject::TvTEvent;
	func7.returnType = AI_TYPE_VOID;
	func7.paramCount = 1;
	func7.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	index++;
	//0xD020016 - 218234903
	AiFunction& func8 = g_GlobalObjectFunctionArray[index];
	func8.wName = g_BlueFlagEvent;
	func8.handler = CGlobalObject::BlueFlagEvent;
	func8.returnType = AI_TYPE_VOID;
	func8.paramCount = 2;
	func8.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func8.param2Type = AI_TYPE_INT;
	index++;
	//0xD020016 - 218234904
	AiFunction& func9 = g_GlobalObjectFunctionArray[index];
	func9.wName = g_RedFlagEvent;
	func9.handler = CGlobalObject::RedFlagEvent;
	func9.returnType = AI_TYPE_VOID;
	func9.paramCount = 2;
	func9.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func9.param2Type = AI_TYPE_INT;
	index++;
	//0xD020016 - 218234905
	AiFunction& func10 = g_GlobalObjectFunctionArray[index];
	func10.wName = g_StopEvent;
	func10.handler = CGlobalObject::StopEvent;
	func10.returnType = AI_TYPE_VOID;
	func10.paramCount = 2;
	func10.param1Type = AI_TYPE_INT;
	func10.param2Type = AI_TYPE_INT;
	index++;	
	//0xD020016 - 218234906
	AiFunction& func11 = g_GlobalObjectFunctionArray[index];
	func11.wName = g_CastBuffForQuestReward;
	func11.handler = CGlobalObject::CastBuffForQuestReward;
	func11.returnType = AI_TYPE_VOID;
	func11.paramCount = 2;
	func11.param1Type = AI_TYPE_SHARED_CREATURE_DATA;
	func11.param2Type = AI_TYPE_INT;
	index++;	

	//reallocate arrays
	UINT64 arrayAddr = reinterpret_cast<UINT64>(g_GlobalObjectFunctionArray);
	WriteDWORD(0x429FAC+3, (UINT)(arrayAddr+8-0x429fb3));
	WriteDWORD(0x429FBF+4, (UINT)(arrayAddr+8-0x400000));
	WriteDWORD(0x42A353+3, (UINT)(arrayAddr+8-0x42A35A));
	WriteDWORD(0x42A360+4, (UINT)(arrayAddr-0x400000));
	WriteDWORD(0x42A395+4, (UINT)(arrayAddr+8-0x400000));
	WriteDWORD(0x42A13b+4, (UINT)(arrayAddr+8-0x400000));
	WriteDWORD(0x42A5A2+4, (UINT)(arrayAddr-0x400000));
	WriteDWORD(0x42A7A7+4, (UINT)(arrayAddr-0x400000));
	WriteDWORD(0x42A14a+4, (UINT)(arrayAddr+0x10-0x400000));

}