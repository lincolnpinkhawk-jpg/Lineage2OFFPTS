#pragma once

struct SchemeBuff
{
	int id;
	SkillPchId skill;
	int minLevel;
	int maxLevel;
	ItemReq price;
	ItemReq requiredItem;
	int abnormalTime;
	int abnormalTime2;
	CSkillInfo *pSI;
};

struct SchemeMacro
{
	int minLevel;
	int maxLevel;
	ItemReq price;
	ItemReq requierdItem;
	int abnormalTime;
	vector<CSkillInfo*> buffs;
};

class CSchemeBuffer
{
	BOOL m_Enabled;
	UINT m_ReloadTime;
	SchemeBuff m_EmptyBuff;
	vector<SchemeBuff> m_Buffs;
	vector<SchemeBuff> m_RemoteBuffs;
	BOOL m_AllowPK;
	BOOL m_AllowGuilty;
	BOOL m_AllowCombat;
	BOOL m_AllowOlympiad;
	BOOL m_AllowCursedWeapon;
	BOOL m_AllowEventFight;
	BOOL m_PeaceZoneOnly;
	BOOL m_PeaceZoneOnlySchemeR;
	BOOL m_LowLevelMsg;
	BOOL m_HighLevelMsg;
	BOOL m_NotEnoughAdenaMsg;
	BOOL m_AddToListMsg;
	BOOL m_AddToSummonListMsg;
	UINT m_BuffDelay;
	UINT m_UseDelay;
	UINT m_freeLevel;
	ItemReq m_UseListPrice;
	map<wstring, SchemeMacro> m_Macro;
	map<wstring, SchemeMacro> m_MacroRemote;
	void LoadData();
public:
	CSchemeBuffer();
	~CSchemeBuffer();
	void Init();
	void RequestReload();
	void TimerExpired();
	bool CanUse(User *pUser);
	SchemeBuff& Get(UINT buffId, bool remote);
	bool RequestBuff(User *pUser, UINT buffId, bool summon, bool remote = false, int nbufftime = 0);
	bool RequestAddToList(User *pUser, UINT buffId, bool summon, bool remote, int Id);
	bool RequestUseList(User *pUser, bool summon, bool remote, int abuse, int Id);
	bool RequestClearList(User *pUser, bool summon, bool remote, int Id);
	bool RequestRecovery(User *pUser, bool summon);
	bool RequestDispelAll(User *pUser, bool summon);
	void ValidateBuffList(User *pUser, bool summon, bool remote, int Id);
	void UseMacro(User *pUser, wstring macro, bool pet, bool remote);
	inline UINT GetBuffDelay() { return m_BuffDelay; };
	inline BOOL IsEnabled() { return m_Enabled; };
	inline BOOL IsAllowInOlympiad() { return m_AllowOlympiad; };
	inline BOOL IsAllowInEventFight() { return m_AllowEventFight; };
};

extern CSchemeBuffer g_SchemeBuffer;