#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include "signer.h"

#ifdef _WIN32
#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#define __open open
#define __read read
#define __close close
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#define __open  open
#define __read  read
#define __close close
#endif

#ifndef TRUE
#define TRUE    1
#endif
#ifndef FALSE
#define FALSE   0
#endif

bool Signer::SecureKeyByIDPW(char *buf, DWORD dwBuf)
{
	if(((KeyFileFormat *)buf)->wSignFlag == 0)
	{
		m_siErrorCode = -2;
		return false;
	};
	DWORD dwCRC[4];
	szptr szIDPW = m_szUserName;
	szIDPW += m_szPassword;
	Keys::CountCrcMD4(dwCRC, szIDPW, szIDPW.strlen());

	dwCRC[0] = SwitchIndian(dwCRC[0]);
	dwCRC[1] = SwitchIndian(dwCRC[1]);
	dwCRC[2] = SwitchIndian(dwCRC[2]);
	dwCRC[3] = SwitchIndian(dwCRC[3]);

	char *ptrKey = ((KeyFileFormat *)buf)->ptrBuffer;
	DWORD dwKeyLen = dwBuf-(ptrKey-buf) - 6;
	ptrKey += 6;
	for(DWORD dwProc=0; dwProc<dwKeyLen; dwProc+=sizeof(dwCRC))
		for(int k=0; k<sizeof(dwCRC)&&(dwProc+k)<dwKeyLen; k++)
			*(ptrKey+dwProc+k) ^= ((char *)dwCRC)[k];
	return true;
}


bool Signer::SecureKeyByIDPWHalf(char *buf, DWORD dwBuf)
{
	if(((KeyFileFormat *)buf)->wSignFlag == 0)
	{
		m_siErrorCode = -2;
		return false;
	};
	DWORD dwCRC[4];
	szptr szIDPW = m_szUserName;
	int len = (int) strlen(m_szPassword)/2 + 1;
	if (len > 1)
	{
		char* pBuf = new char[len];
		strncpy(pBuf, m_szPassword, len-1);
		pBuf[len-1] = '\0';
		szIDPW += pBuf;

		delete [] pBuf;
	}
	Keys::CountCrcMD4(dwCRC, szIDPW, szIDPW.strlen());

	dwCRC[0] = SwitchIndian(dwCRC[0]);
	dwCRC[1] = SwitchIndian(dwCRC[1]);
	dwCRC[2] = SwitchIndian(dwCRC[2]);
	dwCRC[3] = SwitchIndian(dwCRC[3]);

	char *ptrKey = ((KeyFileFormat *)buf)->ptrBuffer;
	DWORD dwKeyLen = dwBuf-(ptrKey-buf) - 6;
	ptrKey += 6;
	for(DWORD dwProc=0; dwProc<dwKeyLen; dwProc+=sizeof(dwCRC))
		for(int k=0; k<sizeof(dwCRC)&&(dwProc+k)<dwKeyLen; k++)
			*(ptrKey+dwProc+k) ^= ((char *)dwCRC)[k];
	return true;
}
//---------------------------------------------------------
void Signer::SetKeyFromCL( int flag, char *KeyBuf )
{
	KeyFromCL = FALSE;
	if( flag == TRUE ) KeyFromCL = TRUE;
	memcpy( (void *) szKeyData, (const void *)KeyBuf, 164 );
}
//---------------------------------------------------------

int Signer::LoadKeys()
{
	bool bKeysReaded = false, bNotOldFmt = false;
	int nReaden;
	int errLoadKey;
	int fh = -1;
	int st_size = 0;
	const int nMaxBufLen = 164; 
	char pBufRead[164];   // Here Keys must be
	m_siErrorCode = 0;
	KeyFromCL = FALSE;


	if(!val) {
#ifdef O_BINARY
		fh = __open( m_szKeyFileName, O_RDONLY | O_BINARY);
#else
		fh = __open( m_szKeyFileName, O_RDONLY);
#endif

		if( fh == -1 )
		{
			m_siErrorCode = 2;//errno;
			return false;
		}

		st_size = lseek(fh, 0, SEEK_END);
		lseek(fh, 0, SEEK_SET);
		if (st_size == lMinKeyFileSize)
		{
			// load 164 bytes from "small" keys file
			nReaden = __read( fh, pBufRead, nMaxBufLen );
			bKeysReaded = (nReaden == lMinKeyFileSize);
		}
		__close( fh );

		memBuf = new char [nMaxBufLen];
		memcpy (memBuf, pBufRead, nMaxBufLen);
		val = true;
	
	} 
	else {
		memcpy (pBufRead, memBuf, nMaxBufLen);
		bKeysReaded = true;
	}
	//*************************************************************************

	if(bKeysReaded)
	{
		SecureKeyByIDPWHalf(pBufRead, lMinKeyFileSize);
		WORD old_SignFlag;
		old_SignFlag = ((KeyFileFormat *)pBufRead)->wSignFlag;
		((KeyFileFormat *)pBufRead)->wSignFlag = 0;
		errLoadKey = keys.LoadFromBuffer( pBufRead, lMinKeyFileSize );
		if(errLoadKey)
		{
			// Restore for correct Loading (CRC) !
			((KeyFileFormat *)pBufRead)->wSignFlag = old_SignFlag;
			SecureKeyByIDPWHalf(pBufRead, lMinKeyFileSize); // restore buffer

			SecureKeyByIDPW(pBufRead, lMinKeyFileSize);

			((KeyFileFormat *)pBufRead)->wSignFlag = 0;
			errLoadKey = keys.LoadFromBuffer( pBufRead, lMinKeyFileSize );
		}
		
		if( !errLoadKey )
			bKeysReaded = true;
		else
		{
			Keys flushKey;
			keys = flushKey;
			m_siErrorCode = -3;
		}
	}

	return bKeysReaded;
}

Signer::Signer(const char * szLogin, const char *szPassword, const char *szKeyFileName)
	: m_szUserName(szLogin), m_szPassword(szPassword), m_szKeyFileName(szKeyFileName)
{
	m_siErrorCode = 0;
	isIgnoreKeyFile = false;
	isIgnoreIniFile = false;
	isKWMFileFromCL = false;
	memset(szKeyData, 0, MAXBUF+1);
	Key64Flag = FALSE;
}

short Signer::ErrorCode()
{
	return m_siErrorCode;
}

bool Signer::Sign(const char *szIn, szptr& szSign)
{
#ifdef _DEBUG
	//printf("\n\rSign - Start !");
#endif

	if (!LoadKeys())
	{
		puts("!LoadKeys");
		return false;
	}
#ifdef _DEBUG
	//printf("\n\rSign - Load Keys");
#endif

	if(!keys.wEKeyBase || !keys.wNKeyBase)
		return false;

	return true;
}
//----
