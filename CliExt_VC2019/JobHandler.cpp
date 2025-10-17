#include "stdafx.h"
#include "JobHandler.h"

CJobHandler g_JobHandler;

CJobHandler::CJobHandler()
{
	m_ExpireTime = time(0);
}

#pragma optimize("", off)

CJobHandler::~CJobHandler()
{
//VM_TIGER_RED_START; //dd5	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	{
		AUTO_LOCK(m_Lock);
		for(UINT n=0;n<m_Jobs.size();n++)
		{
			CJob *pJob = m_Jobs[n];
			if(!pJob->IsDone())
			{
				pJob->Terminate();
				delete pJob;
			}
		}
		m_Jobs.clear();
	}
//VM_TIGER_RED_END; //dd5	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

void CJobHandler::AddJob(CJob *pJob)
{
//VM_TIGER_RED_START; //dd5	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	{
		AUTO_LOCK(m_Lock);
		m_Jobs.push_back(pJob);
		pJob->Start();
	}
//VM_TIGER_RED_END; //dd5	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}

void CJobHandler::TimerExpired()
{
//VM_TIGER_RED_START; //dd5	//VM_TIGER_RED_START; //dd5		VIRTUALIZER_START;
	{
		AUTO_LOCK(m_Lock);
		//each time it's called it will delete only 1 expired job - so it can remove 1 job per TimerExpired call!
		for(vector<CJob*>::iterator it = m_Jobs.begin(); it != m_Jobs.end(); it++)
		{
			CJob *pJob = (*it);
			if(pJob->IsDone())
			{
				m_Jobs.erase(it);
				delete pJob;
				break;
			}
		}
	}
	m_ExpireTime = time(0);

//VM_TIGER_RED_END; //dd5	//VM_TIGER_RED_END; //dd5		VIRTUALIZER_END;
}




#pragma optimize("", on)