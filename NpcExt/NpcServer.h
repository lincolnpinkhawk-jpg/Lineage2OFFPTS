#pragma once

enum NPC_PACKET_IN
{
	TEST_NPC_OPCODE,
	INITIALIZE_ERA,
	PROCESSING_ERA_NPC_DONE,
	CHANGE_ERA,
	TELEPORT_MPCC,
	TELEPORT_MPCC_BY_INDEX,
	SET_PC_LEVEL,
	ADD_PC_SOCIAL,
	UPDATE_PLEDGE_NAME_VALUE,
	FLAG_PLAYER,
	TVT_EVENT,
	BLUE_FLAG_EVENT,
	RED_FLAG_EVENT,
	STOP_EVENT,
	CAST_BUFF_FOR_QUEST_REWARD_VALUE,
	ANNOUNCE_ANTICIPADO

};

class CNpcServer
{
	CNpcServer* Instance;
public:
	CNpcServer();
	inline CSocket* GetSocket()
	{
		UINT64 addr = (UINT64)Instance;
		addr += 0x4030;
		return (CSocket*)(*(PUINT64)addr);
	}
	void Send(const char *format, ...);
};

extern CNpcServer g_NpcServer;